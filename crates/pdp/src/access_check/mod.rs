//! The object-ACL check of layer 5: `acl_grants`.
//!
//! Spec: docs/11 §5 (`acl_grants(s, sd, right) -> bool`: the AD access-check
//! model — DACL, ACEs, inheritance, the subject's SIDs — so that management
//! tools work; D37); [MS-DTYP] 2.5.3.2 (the access check algorithm); [MS-ADTS]
//! 5.1.3.3.2-5.1.3.3.4 (the directory-object rules: simple access,
//! object-specific access over the object type tree — object classes,
//! property sets, properties — and control access rights).
//!
//! # How the two specifications are combined
//!
//! [MS-DTYP] 2.5.3.2 explicitly defers to [MS-ADTS] for Active Directory
//! ("Active Directory has its own checking rules"; 2.4.4.3: "For more
//! information on access checks and object access, see [MS-ADTS] section
//! 5.1.3.3.3"), and the two texts do not agree on every case (owner implicit
//! rights; a non-object deny after an object grant; an object deny on a
//! property set after a grant on one of its attributes; WRITE_OWNER). Both
//! are transcribed separately — `evaluate_token.rs` for [MS-DTYP] 2.5.3.2 and
//! `adts.rs` for [MS-ADTS] 5.1.3.3.x — and **a right is granted only if every
//! applicable procedure grants it**. Where they agree this is simply their
//! common result; where they differ it is the stricter one (fail closed —
//! AGENTS.md §6; D40). The divergences are recorded in Q-050 (resolved,
//! A-21) and Q-051 (interim conjunction kept; deferred to owner item P-8 and
//! the lab recording, docs/44). The conjunction is a subset of each
//! procedure's result, so it can never grant more than either text.
//!
//! | Request ([`Right`]) | Procedures that must all grant |
//! |---|---|
//! | `Object` (whole object) | [MS-DTYP] 2.5.3.2 + [MS-ADTS] 5.1.3.3.2 |
//! | `Property` | [MS-DTYP] 2.5.3.2 + [MS-ADTS] 5.1.3.3.3 |
//! | `CreateChild` | [MS-DTYP] 2.5.3.2 + [MS-ADTS] 5.1.3.3.3 |
//! | `ControlAccess` | [MS-DTYP] 2.5.3.2 + [MS-ADTS] 5.1.3.3.4 |
//!
//! # Project rules stricter than the specifications (docs/11 §5, D37; A-21)
//!
//! - 5a: an absent DACL ⇒ deny (the specs grant everything); an empty DACL
//!   grants nothing except the owner's implied right.
//! - 5b: any ACE type other than the four access ACE types in the DACL ⇒
//!   deny (the specs would evaluate or skip it).
//! - Owner implicit rights (A-21, Q-050): READ_CONTROL only — never
//!   WRITE_DAC (the BlockOwnerImplicitRights mode of [MS-ADTS] 5.1.3.3.1 /
//!   6.1.3.4, hard-wired for every requester) and never WRITE_OWNER
//!   ([`rights::OWNER_IMPLICIT_RIGHTS`]).
//!
//! 5a and 5b are applied by `PreparedDacl::prepare` (dacl.rs), before any
//! evaluator runs; the owner rule by both evaluators' owner steps. Rules 5c
//! (attribute class) and 5d (tier) belong to `decide` (decide.rs), layers 5
//! and 4.

mod adts;
mod dacl;
mod evaluate_token;
mod object_tree;
pub mod rights;
mod token;

use dtyp::{Guid, SecurityDescriptor, Sid};

pub use dacl::DaclRefusal;

use crate::model::Subject;
use dacl::PreparedDacl;
use object_tree::ObjectTypeList;
use rights::{DIRECTORY_RIGHTS, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_CREATE_CHILD};
use token::AccessContext;

/// The right a request needs on a directory object. Spec: docs/11 §4-§5
/// (`desired_right(req.action)`, `acl_grants(.., right: Right)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Right {
    /// Rights on the object as a whole (e.g. RIGHT_DELETE,
    /// RIGHT_DS_LIST_CONTENTS, RIGHT_READ_CONTROL, or RIGHT_DS_READ_PROPERTY
    /// on all attributes). Spec: [MS-ADTS] 5.1.3.3.2.
    Object {
        /// The requested rights: non-zero, only [`rights::DIRECTORY_RIGHTS`].
        mask: u32,
    },
    /// Rights on one attribute (RIGHT_DS_READ_PROPERTY /
    /// RIGHT_DS_WRITE_PROPERTY). Spec: [MS-ADTS] 3.1.1.4.3 ("granted rights
    /// RIGHT_DS_READ_PROPERTY on OA"), 5.1.3.3.3.
    Property {
        /// The requested rights: non-zero, only [`rights::DIRECTORY_RIGHTS`].
        mask: u32,
        /// The attribute's property set (attributeSecurityGUID), if any.
        property_set: Option<Guid>,
        /// The attribute's schemaIDGUID.
        attribute: Guid,
    },
    /// RIGHT_DS_CREATE_CHILD for a child of the given class. Spec: [MS-ADTS]
    /// 3.1.1.5.2.1 ("the requester MUST have RIGHT_DS_CREATE_CHILD on the
    /// parent object for the objectClass of the object being added"),
    /// 5.1.3.2 (CC and ObjectType).
    CreateChild {
        /// The child's objectClass schemaIDGUID.
        class: Guid,
    },
    /// The control access right identified by `right`. Spec: [MS-ADTS]
    /// 5.1.3.2.1, 5.1.3.3.4.
    ControlAccess {
        /// The rightsGuid.
        right: Guid,
    },
}

/// What the access check needs to know about the object besides its
/// security descriptor. Spec: [MS-ADTS] 5.1.3.3.3 (root of the object type
/// tree), 5.1.3.3 (Principal Self substitution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirObjectContext {
    /// The schemaIDGUID of the object's class.
    pub object_class: Guid,
    /// The object's objectSid, if it has one (substituted for
    /// PRINCIPAL_SELF).
    pub object_sid: Option<Sid>,
}

/// Check the project's preconditions on a descriptor's DACL (rules 5a, 5b
/// and structural validity) without evaluating it. `acl_grants` denies
/// whenever this returns `Err`. Spec: dacl.rs module documentation.
pub fn dacl_preconditions(sd: &SecurityDescriptor) -> Result<(), DaclRefusal> {
    PreparedDacl::prepare(sd).map(|_| ())
}

/// Does `sd` grant `subject` the `right` on the object?
///
/// Spec: docs/11 §5; [MS-DTYP] 2.5.3.2; [MS-ADTS] 5.1.3.3.2-5.1.3.3.4; the
/// combination and the stricter rules are described in the module
/// documentation. Total and panic-free: anything unexpected yields `false`.
#[must_use]
pub fn acl_grants(
    subject: &Subject,
    sd: &SecurityDescriptor,
    object: &DirObjectContext,
    right: &Right,
) -> bool {
    // Rules 5a / 5b and structural validity (dacl.rs).
    let dacl = match PreparedDacl::prepare(sd) {
        Ok(dacl) => dacl,
        Err(_) => return false,
    };
    let ctx = AccessContext::new(subject, object.object_sid.as_ref(), sd.owner_sid.as_ref());
    match *right {
        Right::Object { mask } => {
            let tree = ObjectTypeList::object(object.object_class);
            valid_request(mask)
                && evaluate_token::evaluate_token_against_descriptor(&ctx, &dacl, mask, &tree)
                && adts::check_simple_access(&ctx, &dacl, mask)
        }
        Right::Property {
            mask,
            property_set,
            attribute,
        } => {
            let tree = ObjectTypeList::property(object.object_class, property_set, attribute);
            valid_request(mask)
                && evaluate_token::evaluate_token_against_descriptor(&ctx, &dacl, mask, &tree)
                && adts::check_object_specific_access(&ctx, &dacl, mask, &tree)
        }
        Right::CreateChild { class } => {
            let tree = ObjectTypeList::object_and(object.object_class, class);
            evaluate_token::evaluate_token_against_descriptor(
                &ctx,
                &dacl,
                RIGHT_DS_CREATE_CHILD,
                &tree,
            ) && adts::check_object_specific_access(&ctx, &dacl, RIGHT_DS_CREATE_CHILD, &tree)
        }
        Right::ControlAccess { right } => {
            // [MS-DTYP] 2.5.3.2 with the right's GUID as a level-1 node
            // ([MS-DTYP] 2.4.4.3: for CR "The ObjectType GUID identifies an
            // extended access right"), and [MS-ADTS] 5.1.3.3.4.
            let tree = ObjectTypeList::object_and(object.object_class, right);
            evaluate_token::evaluate_token_against_descriptor(
                &ctx,
                &dacl,
                RIGHT_DS_CONTROL_ACCESS,
                &tree,
            ) && adts::check_control_access(&ctx, &dacl, &right)
        }
    }
}

/// A request mask must name at least one right and only the specific rights
/// of the [MS-ADTS] 5.1.3.2 diagram — no generic right, no ignored X bit, no
/// MAXIMUM_ALLOWED / ACCESS_SYSTEM_SECURITY. A malformed request is denied
/// (fail closed, D40). Spec: [MS-ADTS] 5.1.3.2.
fn valid_request(mask: u32) -> bool {
    mask != 0 && mask & !DIRECTORY_RIGHTS == 0
}
