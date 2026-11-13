//! EvaluateTokenAgainstDescriptor — the [MS-DTYP] 2.5.3.2 access check.
//!
//! Spec: [MS-DTYP] v20241119 2.5.3.2 (Access Check Algorithm Pseudocode),
//! transcribed clause by clause below for the non-MAXIMUM_ALLOWED mode, with
//! an Object Tree ([MS-DTYP] 2.3.9) always supplied (for a whole-object
//! request it holds only the object itself).
//!
//! Scope notes:
//! - `GrantedAccess` is not produced: it is an output only used by the
//!   MAXIMUM_ALLOWED mode, which this crate does not support (a request
//!   naming MAXIMUM_ALLOWED is denied — fail closed).
//! - `AccessCheck` (the outer routine) adds only the central access policy
//!   step. `GetCentralizedAccessPolicy` ([MS-DTYP] 2.5.3.1.4) returns NULL
//!   when "No central access policy is present in the configuration", which
//!   is always the case here, and then AccessCheck returns the result of
//!   EvaluateTokenAgainstDescriptor unchanged ("ELSE Return success").
//! - The "Allow Access Callback Ace" case is unreachable: callback ACEs are
//!   refused before evaluation (project rule 5b, see `dacl.rs`).
//! - Mandatory integrity ([MS-DTYP] 2.5.3.3) is not implemented; [MS-DTYP]
//!   2.5.2 makes it optional ("If an implementation also chooses to implement
//!   mandatory integrity ...").
//!
//! Result for a request with an object tree: the pseudocode's final test is
//! "IF RemainingAccess to 0 THEN Return success". For a whole-object request
//! (tree = the object only) that test is used as written. For a request about
//! a sub-object (property, child class, control access right), the per-node
//! `Remaining` of the target node is the result ([MS-DTYP] 2.3.9: "Remaining:
//! Remaining access bits for this element"; the 2.5.3.2 comment "if the
//! requestor is granted access to a specific node, this will grant access to
//! all its children"; [MS-ADTS] 5.1.3.3.3 step 4 checks the target node). The
//! top-level `RemainingAccess` is only reduced by non-object ACEs, so using it
//! for sub-objects would make every object ACE ineffective. Recorded in Q-051.

use super::dacl::PreparedDacl;
use super::object_tree::ObjectTypeList;
use super::rights::{ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED, OWNER_IMPLICIT_RIGHTS};
use super::token::{AccessContext, AceKind};

/// EvaluateTokenAgainstDescriptor in the non-MAXIMUM_ALLOWED mode; `true` is
/// "Return success", `false` is "Return access_denied".
/// Spec: [MS-DTYP] 2.5.3.2.
pub(crate) fn evaluate_token_against_descriptor(
    ctx: &AccessContext<'_>,
    dacl: &PreparedDacl,
    access_request_mask: u32,
    object_tree: &ObjectTypeList,
) -> bool {
    // "Set RemainingAccess to Access Request mask".
    let mut remaining_access = access_request_mask;

    // "IF RemainingAccess contains ACCESS_SYSTEM_SECURITY access bit THEN IF
    // Token.Privileges contains SeSecurityPrivilege THEN ... ELSE ... Return
    // access_denied". Token.Privileges is empty in this model (token.rs).
    if remaining_access & ACCESS_SYSTEM_SECURITY != 0 {
        return false;
    }

    // "IF RemainingAccess contains WRITE_OWNER access bit and Token.Privileges
    // is not NULL THEN IF Token.Privileges contains SeTakeOwnershipPrivilege
    // THEN Remove WRITE_OWNER ...". No privileges: nothing is removed.

    // "-- the owner of an object is always granted READ_CONTROL and WRITE_DAC.
    // CALL SidInToken(Token, SecurityDescriptor.Owner, PrincipalSelfSubst) IF
    // SidInToken returns True THEN IF DACL does not contain ACEs from object
    // owner THEN Remove READ_CONTROL and WRITE_DAC from RemainingAccess".
    // DELIBERATE DEVIATION (A-21, Q-050 resolved): only READ_CONTROL is
    // removed — the BlockOwnerImplicitRights behaviour of [MS-ADTS] 5.1.3.3.1 /
    // 6.1.3.4 is hard-wired (see `OWNER_IMPLICIT_RIGHTS`). "ACEs from object
    // owner": read as in `contains_aces_from_owner` (Q-050).
    if ctx.owner_in_token() && !dacl.contains_aces_from_owner(ctx.owner()) {
        remaining_access &= !OWNER_IMPLICIT_RIGHTS;
    }

    // "IF RemainingAccess contains MAXIMUM_ALLOWED access bit THEN Set
    // MaxAllowedMode to TRUE". MaxAllowedMode is not supported: deny.
    if remaining_access & MAXIMUM_ALLOWED != 0 {
        return false;
    }

    // "IF Object Tree is not NULL THEN Set LocalTree to Object Tree ... FOR
    // each node in LocalTree DO Set node.Remaining to RemainingAccess".
    let mut node_remaining = vec![remaining_access; object_tree.node_count()];

    // "FOR each ACE in DACL DO".
    for ace in dacl.entries() {
        // "IF ACE.AceFlags does not contain INHERIT_ONLY_ACE THEN".
        if ace.inherit_only {
            continue;
        }
        // "CASE ACE.Type OF". (An object ACE without ObjectType was
        // normalised to the simple type — dacl.rs.)
        match (ace.kind, ace.object_type) {
            // "CASE Allow Access: CALL SidInToken( Token, ACE.Sid, ... ) IF
            // SidInToken returns True THEN ... Remove ACE.AccessMask from
            // RemainingAccess ... FOR each node in LocalTree DO Remove
            // ACE.AccessMask from node.Remaining".
            (AceKind::Grant, None) => {
                if ctx.ace_applies(&ace.sid, AceKind::Grant) {
                    remaining_access &= !ace.mask;
                    for remaining in node_remaining.iter_mut() {
                        *remaining &= !ace.mask;
                    }
                }
            }
            // "CASE Deny Access: IF ACE.AccessMask equals 0 returns True THEN
            // Break" (leave this CASE: the ACE has no effect) "CALL
            // SidInToken( Token, ACE.Sid, PrincipalSelfSubst ) IF SidInToken
            // returns True THEN ... IF any bit of RemainingAccess is in
            // ACE.AccessMask THEN ... Return access_denied".
            (AceKind::Deny, None) => {
                if ace.mask == 0 {
                    continue;
                }
                if ctx.ace_applies(&ace.sid, AceKind::Deny) && remaining_access & ace.mask != 0 {
                    return false;
                }
            }
            // "CASE Object Allow Access: CALL SidInToken(...) IF SidInToken
            // returns True THEN IF ACE.Object is contained in LocalTree THEN
            // Locate node n in LocalTree such that n.GUID is the same as
            // ACE.Object; Remove ACE.AccessMask from n.Remaining; FOR each node
            // ns such that ns is a descendent of n DO Remove ACE.AccessMask
            // from ns.Remaining; FOR each node np such that np is an ancestor
            // of n DO Set np.Remaining to np.Remaining or np-1.Remaining".
            (AceKind::Grant, Some(object_type)) => {
                if !ctx.ace_applies(&ace.sid, AceKind::Grant) {
                    continue;
                }
                let Some(n) = object_tree.locate(&object_type) else {
                    continue;
                };
                // n and its descendants (the nodes after it in the chain).
                for remaining in node_remaining.iter_mut().skip(n) {
                    *remaining &= !ace.mask;
                }
                // Ancestors, walking up from n: np.Remaining |= the
                // Remaining of the node one level below np on the path.
                let mut below = n;
                while below > 0 {
                    let child = node_remaining.get(below).copied().unwrap_or(0);
                    if let Some(parent) = node_remaining.get_mut(below - 1) {
                        *parent |= child;
                    }
                    below -= 1;
                }
            }
            // "CASE Object Deny Access: CALL SidInToken(...) IF SidInToken
            // returns True THEN Locate node n in LocalTree such that n.GUID is
            // the same as ACE.Object; IF n exists THEN If any bit of
            // n.Remaining is in ACE.AccessMask THEN ... Return access_denied".
            (AceKind::Deny, Some(object_type)) => {
                if !ctx.ace_applies(&ace.sid, AceKind::Deny) {
                    continue;
                }
                if let Some(n) = object_tree.locate(&object_type) {
                    let remaining = node_remaining.get(n).copied().unwrap_or(0);
                    if remaining & ace.mask != 0 {
                        return false;
                    }
                }
            }
        }
    }

    // "IF RemainingAccess to 0 THEN Return success Else Return access_denied"
    // — for a sub-object request, the target node's Remaining (module note).
    if object_tree.node_count() <= 1 {
        remaining_access == 0
    } else {
        node_remaining.last().is_some_and(|r| *r == 0)
    }
}
