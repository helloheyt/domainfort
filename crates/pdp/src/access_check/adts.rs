//! The Active Directory access-check rules of [MS-ADTS] 5.1.3.3.
//!
//! Spec: [MS-ADTS] v20261026 5.1.3.3.2 (Checking Simple Access), 5.1.3.3.3
//! (Checking Object-Specific Access), 5.1.3.3.4 (Checking Control Access
//! Right-Based Access); 5.1.3.1 (end of DACL without an explicit grant ⇒
//! deny); 5.1.3.3 (the descriptor is evaluated after the Principal Self
//! substitution — done by `AccessContext::sid_in_token`). [MS-DTYP] 2.5.3.2
//! defers to these rules for directory objects ("Active Directory has its own
//! checking rules"), and so does [MS-DTYP] 2.4.4.3 for object ACEs ("see
//! [MS-ADTS] section 5.1.3.3.3").
//!
//! Rule 1 of each procedure ("If the security descriptor has no DACL or its
//! 'DACL Present' (DP) bit is not set, then grant the requester all possible
//! access rights") never runs: project rule 5a refuses such descriptors
//! before evaluation (`dacl.rs`).
//!
//! "the access rights in M are not in X, then add the rights in M to Y" is
//! applied per right: `Y |= M & !X`. (For a single node this gives the same
//! outcome as the [MS-DTYP] 2.5.3.2 rules "Remove ACE.AccessMask from
//! RemainingAccess" / "IF any bit of RemainingAccess is in ACE.AccessMask
//! THEN ... access_denied".)
//!
//! Which node of the object type tree an object ACE names ("let O be an
//! object of class c"; "the unique node such that Guid(v) = g") follows
//! project decision A-28 (Q-081), described in object_tree.rs.
//!
//! [MS-ADTS] 5.1.3.3.5 (validated writes) is not implemented: no action of
//! docs/11 §1 is authorised by RIGHT_DS_WRITE_PROPERTY_EXTENDED, so a write is
//! authorised only by RIGHT_DS_WRITE_PROPERTY (fewer grants, never more).

use dtyp::Guid;

use super::dacl::PreparedDacl;
use super::object_tree::ObjectTypeList;
use super::rights::{OWNER_IMPLICIT_RIGHTS, RIGHT_DS_CONTROL_ACCESS};
use super::token::{AccessContext, AceKind};

/// Checking Simple Access. Spec: [MS-ADTS] 5.1.3.3.2.
///
/// Only simple ACEs are considered ("standard access rights specified in
/// simple ACEs"); after normalisation that includes object ACEs without
/// ObjectType (`dacl.rs`), and excludes object ACEs that carry one.
pub(crate) fn check_simple_access(
    ctx: &AccessContext<'_>,
    dacl: &PreparedDacl,
    requested: u32,
) -> bool {
    // "Let G and D denote the access rights that are granted and denied ...
    // Set both to a value of 0 initially."
    let mut granted = 0u32;
    let mut denied = 0u32;

    // Rule 2: "If the DACL does not have any ACE, then grant the requester no
    // access rights on the object." No ACE can add to G; the owner's implied
    // rights below still apply — "even with an empty DACL, some rights are
    // implied ... the current OWNER of an object is implicitly granted
    // RIGHT_READ_CONTROL and RIGHT_WRITE_DAC" (5.1.3.3.1; also [MS-DTYP]
    // 2.5.3.2: "except through the implied access of the owner") — of which
    // only READ_CONTROL is kept here (A-21, rule 3 below).

    // Rule 3: "If the SID in the Owner field of the object's security
    // descriptor matches any SID in the requester's security context, then
    // add the bits 'Read Control' (RC), 'Write DACL' (WD) and 'Write Owner'
    // (WO) to G." DELIBERATE DEVIATION (A-21, Q-050 resolved): only
    // `OWNER_IMPLICIT_RIGHTS` (READ_CONTROL) is added — WD is blocked as in the
    // BlockOwnerImplicitRights mode of 5.1.3.3.1 / 6.1.3.4, and WO is implied
    // only with SE_TAKE_OWNERSHIP_PRIVILEGE (5.1.3.3.1), which this model
    // has no notion of.
    if ctx
        .owner()
        .is_some_and(|owner| ctx.in_security_context(owner))
    {
        granted |= OWNER_IMPLICIT_RIGHTS;
    }

    // Rule 4: "Evaluate the DACL by examining each ACE in sequence, starting
    // with the first ACE ... Let the ACCESS_MASK field of the ACE have a value
    // M."
    for ace in dacl.entries() {
        // 4.1 "If the 'Inherit Only' (IO) flag is set in the ACE, skip the
        // ACE."
        if ace.inherit_only {
            continue;
        }
        // Simple ACEs only (an ObjectType makes it object-specific).
        if ace.object_type.is_some() {
            continue;
        }
        // 4.2 "If the SID in the ACE does not match any SID in the
        // requester's security context, skip the ACE."
        if !ctx.ace_applies(&ace.sid, ace.kind) {
            continue;
        }
        match ace.kind {
            // 4.3 "If the ACE type is 'Access Denied' and the access rights in
            // M are not in G, then add the rights in M to D."
            AceKind::Deny => denied |= ace.mask & !granted,
            // 4.4 "If the ACE type is 'Access Allowed' and the access rights in
            // M are not in D, then add the rights in M to G."
            AceKind::Grant => granted |= ace.mask & !denied,
        }
    }

    // Rule 5: "the access rights in G is the maximum standard access available
    // to the requester on the object. Check the requested access mask against
    // the access rights granted in G."
    requested & !granted == 0
}

/// Checking Object-Specific Access over the object type tree of one request.
/// Spec: [MS-ADTS] 5.1.3.3.3.
///
/// The tree is a chain (object_tree.rs), so no node has a sibling and the
/// sibling condition of step 5.2 holds vacuously.
pub(crate) fn check_object_specific_access(
    ctx: &AccessContext<'_>,
    dacl: &PreparedDacl,
    requested: u32,
    tree: &ObjectTypeList,
) -> bool {
    // Rule 2: "If the DACL does not have any ACE, then grant the requester no
    // access rights on the object."
    if dacl.is_empty() {
        return false;
    }
    // "label each node v ... with two additional labels called Grant(v) and
    // Deny(v) ... Set both labels to a value 0 initially for every node."
    let nodes = tree.node_count();
    let mut grant = vec![0u32; nodes];
    let mut deny = vec![0u32; nodes];

    // Rule 3: "Evaluate the DACL by examining each ACE in sequence".
    for ace in dacl.entries() {
        // 3.1 "If the 'Inherit Only' (IO) flag is set in the ACE, skip the
        // ACE."
        if ace.inherit_only {
            continue;
        }
        // 3.2 "If the SID in the ACE does not match any SID in the
        // requester's security context, skip the ACE."
        if !ctx.ace_applies(&ace.sid, ace.kind) {
            continue;
        }
        let m = ace.mask;
        match (ace.kind, ace.object_type) {
            // 3.3 "If the ACE type is 'Access Allowed' and the access rights in
            // M are not in Deny(r), then add the rights in M to Grant(r) ...
            // For every descendant node u of r, if the rights in M are not in
            // Deny(u), then add the rights in M to Grant(u)."
            // 3.4 "Object Access Allowed" without ObjectType: same as 3.3
            // (normalised in dacl.rs).
            (AceKind::Grant, None) => {
                for (g, d) in grant.iter_mut().zip(deny.iter()) {
                    *g |= m & !*d;
                }
            }
            // 3.5 "If the ACE type is 'Object Access Allowed' and the
            // ObjectType field in the ACE contains a GUID value g: If there
            // exists no node v ... such that Guid(v) = g, then skip the ACE.
            // Otherwise ... If the rights in M are not in Deny(v), then add
            // the rights in M to Grant(v). For every descendant node u of v,
            // if the rights in M are not in Deny(u), then add the rights in M
            // to Grant(u)."
            // "the unique node": A-28 (Q-081) — the root only for the most
            // specific class; for a GUID that labels two nodes, only the
            // lower one (`ObjectTypeList::locate_allow`; object_tree.rs).
            (AceKind::Grant, Some(g)) => {
                let Some(v) = tree.locate_allow(&g) else {
                    continue;
                };
                for (gr, d) in grant.iter_mut().zip(deny.iter()).skip(v) {
                    *gr |= m & !*d;
                }
                // 3.5.1 "If v = r, then proceed to the next ACE."
                // 3.5.2 "If Grant(v) = Grant(s) for every sibling s of node v,
                // then add the rights in Grant(v) to Grant(p) where p is the
                // parent of node v." (No siblings in a chain.)
                // 3.5.3 "Set v to p, and repeat these three steps."
                let mut v = v;
                while v > 0 {
                    let granted_v = grant.get(v).copied().unwrap_or(0);
                    if let Some(parent) = grant.get_mut(v - 1) {
                        *parent |= granted_v;
                    }
                    v -= 1;
                }
            }
            // 3.6 "If the ACE type is 'Access Denied' and the access rights in
            // M are not in Grant(r), then add the rights in M to Deny(r). For
            // every descendant node u below the root node, if the rights in M
            // are not in Grant(u), then add the rights in M to Deny(u)."
            // 3.7 "Object Access Denied" without ObjectType: same as 3.6
            // (normalised in dacl.rs).
            (AceKind::Deny, None) => {
                for (d, g) in deny.iter_mut().zip(grant.iter()) {
                    *d |= m & !*g;
                }
            }
            // 3.8 "If the ACE type is 'Object Access Denied' and the ObjectType
            // field in the ACE contains a GUID value g: If there exists no
            // node v ... such that Guid(v) = g, then skip the ACE. Otherwise,
            // let v be the unique node in P such that Guid(v) = g if any such
            // node exists. If no such node exists, let v be the unique node
            // in A such that Guid(v) = g. If the rights in M are not in
            // Grant(v), then add the rights in M to Deny(v). For every
            // descendant node u of v, if the rights in M are not in Grant(u),
            // then add the rights in M to Deny(u). For every ancestor node w
            // of v, add the rights in M to Deny(w)."
            // The text names only property-set (P) and attribute (A) nodes;
            // a GUID equal to the root's (the object class) exists in V but
            // in neither — that gap is filled with v = r, the choice that
            // denies the most (Q-051). A-28 (Q-081): the root is also named
            // by every other class of the object's superclass chain, and a
            // GUID that labels two nodes names the higher one
            // (`ObjectTypeList::locate_deny`; object_tree.rs).
            (AceKind::Deny, Some(g)) => {
                let Some(v) = tree.locate_deny(&g) else {
                    continue;
                };
                for (index, (d, gr)) in deny.iter_mut().zip(grant.iter()).enumerate() {
                    if index < v {
                        *d |= m;
                    } else {
                        *d |= m & !*gr;
                    }
                }
            }
        }
    }

    // Rule 4: "If the requested access is for specific properties on the
    // object, check the requested access mask against the rights granted in
    // Grant(u) where u is the attribute node in tree T that is the target of
    // the request" — the target is the last node of the chain (for a
    // whole-object tree that is r: "check ... against ... Grant(r)").
    grant.last().is_some_and(|g| requested & !*g == 0)
}

/// Checking Control Access Right-Based Access for the control access right
/// identified by `right` (G). Spec: [MS-ADTS] 5.1.3.3.4.
///
/// After normalisation a simple ACE and an object ACE without ObjectType are
/// one form (`object_type: None`); both "control the right to perform all
/// control access right controlled operations" ([MS-ADTS] 5.1.3.2, CR: "If
/// ObjectType does not contain a GUID ..."; 5.1.3.2.1) and are handled by
/// steps 3.3 / 3.5. Recorded in Q-051.
pub(crate) fn check_control_access(
    ctx: &AccessContext<'_>,
    dacl: &PreparedDacl,
    right: &Guid,
) -> bool {
    // Rule 2: "If the DACL does not have any ACE, then deny the requester the
    // requested control access right."
    if dacl.is_empty() {
        return false;
    }
    // Rule 3: "Evaluate the DACL by examining each ACE in sequence".
    for ace in dacl.entries() {
        // 3.1 "If the 'Inherit Only' (IO) flag is set in the ACE, skip the
        // ACE."
        if ace.inherit_only {
            continue;
        }
        // 3.2 "If the SID in the ACE does not match any SID in the
        // requester's security context, skip the ACE."
        if !ctx.ace_applies(&ace.sid, ace.kind) {
            continue;
        }
        // Steps 3.3-3.6 all require "the access right
        // RIGHT_DS_CONTROL_ACCESS (CR) is present in M".
        if ace.mask & RIGHT_DS_CONTROL_ACCESS == 0 {
            continue;
        }
        let names_right = match &ace.object_type {
            None => true,
            Some(object_type) => object_type == right,
        };
        if !names_right {
            continue;
        }
        return match ace.kind {
            // 3.3 / 3.4 "... then grant the requested control access right.
            // Stop any further access checks."
            AceKind::Grant => true,
            // 3.5 / 3.6 "... then deny the requested control access right.
            // Stop any further access checks."
            AceKind::Deny => false,
        };
    }
    // End of the DACL without an explicit grant: "If it comes to the end of
    // the DACL, and the thread's desired access is still not explicitly
    // allowed or denied, the server denies access" (5.1.3.1).
    false
}
