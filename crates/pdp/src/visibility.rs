//! LDAP search: filter, never error.
//!
//! Spec: docs/11 §7 (`decide_visibility(subject, context, candidates) ->
//! Vec<Visible>`; "filter, do not fail — otherwise we would confirm
//! existence"; access-based enumeration); docs/06 §7 ("the PDP is called for
//! each candidate object and each returned attribute"; D15); [MS-ADTS]
//! 3.1.1.4.3 ("the security context of the requester MUST be granted rights
//! RIGHT_DS_LIST_CONTENTS ... on OP"; "MUST be granted rights
//! RIGHT_DS_READ_PROPERTY on OA ... Otherwise, the value is treated as 'does
//! not exist'"), 5.1.3.3.6 (Checking Object Visibility).
//!
//! Every per-object and per-attribute question goes through [`decide`], so
//! all five layers (authn, transport, global rules, tier, ACL + attribute
//! class) apply to search results exactly as to direct reads.
//!
//! Choices (fail closed; fewer results, never more):
//! - "List Object" mode ([MS-ADTS] 5.1.3.3.6, RIGHT_DS_LIST_OBJECT) is not
//!   implemented: an object is visible only through RIGHT_DS_LIST_CONTENTS on
//!   its parent (the default mode — "The default setting is '0'").
//! - [MS-ADTS] 5.1.3.3.6 makes the root object of a naming context visible
//!   without any check. Here no object is visible without a positive
//!   decision (docs/05 §6, docs/11 §7): for a naming-context root (no parent)
//!   the list decision is taken on the root itself.
//! - Visibility filtering is not itself an access decision: the per-object
//!   decisions are not returned, so their audit obligations are not passed
//!   on. The PEP authorises and audits the search operation itself with
//!   [`decide`].

use std::collections::BTreeSet;

use crate::decide::decide;
use crate::model::{AccessRequest, Action, AttrId, Context, Dn, Effect, Resource, Subject};
use crate::pip::Pip;
use crate::policy::PolicySnapshot;

/// A search candidate: the object, its parent (`None` for a naming-context
/// root) and the attributes the search would return. Spec: docs/11 §7
/// (`DirObjectRef`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirObjectRef {
    /// The candidate object.
    pub dn: Dn,
    /// Its parent, or `None` for the root of a naming context.
    pub parent: Option<Dn>,
    /// The attributes the search would return.
    pub attrs: Vec<AttrId>,
}

/// A visible candidate and the subset of its attributes that may be
/// returned. Spec: docs/11 §7 (`Visible { obj, readable_attrs }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visible {
    /// The candidate.
    pub obj: DirObjectRef,
    /// The attributes that may be returned.
    pub readable_attrs: BTreeSet<AttrId>,
}

/// Filter search candidates. Never errors: what is not allowed is simply
/// absent. Spec: docs/11 §7; [MS-ADTS] 3.1.1.4.3, 5.1.3.3.6.
#[must_use]
pub fn decide_visibility<P: Pip + ?Sized>(
    subject: &Subject,
    context: &Context,
    candidates: &[DirObjectRef],
    pol: &PolicySnapshot,
    pip: &P,
) -> Vec<Visible> {
    let allowed = |action: Action, dn: Dn, attr: Option<AttrId>| -> bool {
        let req = AccessRequest {
            subject: subject.clone(),
            resource: Resource::DirObject { dn, attr },
            action,
            context: context.clone(),
        };
        decide(&req, pol, pip).effect == Effect::Allow
    };
    candidates
        .iter()
        .filter_map(|candidate| {
            // RIGHT_DS_LIST_CONTENTS on OP (the parent); on the object itself
            // for a naming-context root (module note).
            let list_target = candidate
                .parent
                .clone()
                .unwrap_or_else(|| candidate.dn.clone());
            if !allowed(Action::DirList, list_target, None) {
                return None;
            }
            // RIGHT_DS_READ_PROPERTY on each OA, plus the attribute class.
            let readable_attrs = candidate
                .attrs
                .iter()
                .filter(|a| allowed(Action::DirRead, candidate.dn.clone(), Some(**a)))
                .copied()
                .collect();
            Some(Visible {
                obj: candidate.clone(),
                readable_attrs,
            })
        })
        .collect()
}
