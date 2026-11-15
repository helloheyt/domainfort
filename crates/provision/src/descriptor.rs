//! The security descriptor of the domain root — the only descriptor with
//! explicit ACEs in a provisioned domain; every other object inherits from
//! it (A-76) through directory-admin's own computation
//! ([`directory_admin::new_object_descriptor`], A-84), so provisioning and
//! the runtime write path compute child descriptors identically.
//!
//! # The root descriptor
//!
//! - OWNER = GROUP = the Tier-0 group's SID (docs/51 §10; A-76).
//! - Control = SR | DP: self-relative, DACL present ([MS-DTYP] 2.4.6); no
//!   SACL (phase 1 has no SACL writer, Q-336 item 6).
//! - DACL, AclRevision = ACL_REVISION_DS (0x04 — object ACEs, [MS-DTYP]
//!   2.4.5), every ACE but row 11 an **allow for the Tier-0 group** with AceFlags =
//!   CONTAINER_INHERIT_ACE only ([MS-DTYP] 2.4.4.1: "Child objects that are
//!   containers … inherit the ACE as an effective ACE. The inherited ACE is
//!   inheritable" — and every directory object is a container for
//!   inheritance, [MS-ADTS] 6.1.3 item 5.3). Each ACE is also effective on
//!   the root itself (INHERIT_ONLY_ACE clear). By decision A-84 (Q-335 /
//!   Q-336): **no INHERIT_ONLY_ACE, no CREATOR_OWNER / CREATOR_GROUP ACE,
//!   no generic bit.**
//! - The rights are exactly the ones `pdp`'s `desired_right` asks for the
//!   operations of docs/51 §5.2 (crates/pdp decide.rs), with the values of
//!   [MS-ADTS] 5.1.3.2 (pdp's `access_check::rights` constants):
//!
//! | # | ACE type ([MS-DTYP] 2.4.4.x) | Mask ([MS-ADTS] 5.1.3.2) | ObjectType | for |
//! |---|---|---|---|---|
//! | 1 | ACCESS_ALLOWED_ACE (2.4.4.2) | RP 0x10 \| LC 0x04 \| DE 0x10000 | — | `DirRead` whole object (visibility, `Lookup`), `DirList`, `DirDelete` |
//! | 2-6 | ACCESS_ALLOWED_OBJECT_ACE (2.4.4.3) | CC 0x01 | the class's schemaIDGUID (user, computer, group, organizationalUnit, container) | `DirAddChild(class)` of rows 1-4 |
//! | 7-9 | ACCESS_ALLOWED_OBJECT_ACE | WP 0x20 | the attribute's schemaIDGUID (userAccountControl, accountExpires, member) | `DirWrite(attr)` of rows 6-8 |
//! | 10 | ACCESS_ALLOWED_OBJECT_ACE | CR 0x100 | User-Force-Change-Password (`00299570-246d-11d0-a768-00aa006e0529`, [MS-ADTS] 6.1.1.2.7.53) | `DirControlRight` of rows 5 (and CompletePasswordSet) |
//! | 11 | ACCESS_ALLOWED_OBJECT_ACE, trustee **PRINCIPAL_SELF** (S-1-5-10), InheritedObjectType = the user class | CR 0x100 | User-Change-Password (`ab721a53-1e2f-11d0-9819-00aa0040529b`, [MS-ADTS] 6.1.1.2.7.52) | kpasswd's `ChangePassword`: the account's own `DirControlRight` (task K9, docs/53 §5.6 step 4) |
//!
//! **Row 11 (task K9).** [MS-ADTS] 3.1.1.3.1.5.1: for a password change the
//! account whose password changes "MUST possess the 'User-Change-Password'
//! control access right on itself". The grant is made once, here, to
//! PRINCIPAL_SELF — the placeholder, in an inheritable ACE on an account
//! object, for the account's own SID ([MS-DTYP] 2.4.2.4); [MS-ADTS] 5.1.3.3:
//! the server replaces it with O!objectSid at the access check (crates/pdp
//! does, [MS-DTYP] 2.5.3.1.1 SidInToken). Its InheritedObjectType
//! is the user class's schemaIDGUID ([MS-DTYP] 2.4.4.3: present ⇒ only that
//! type of child inherits it as effective), so the right is effective on
//! user objects only — phase 1 changes users' passwords only (docs/53
//! R53-1; D104 minimalism) — and passes through the OUs as an inherit-only
//! copy (dtyp's [MS-DTYP] 2.5.3.4 computation, A-84). On the root itself it
//! names the domain SID, which no token holds. docs/questions/Q-974.
//!
//! RIGHT_DS_DELETE_CHILD is not granted: pdp's `DirDelete` asks
//! RIGHT_DELETE on the object only ("The alternative … DELETE_CHILD on the
//! parent … is not implemented"). Every object ACE names its class /
//! attribute / right, so the root grants no more than the closed operation
//! set (minimalism, D104): no CC for domainDNS or any other class, no WP on
//! any other attribute (nTSecurityDescriptor included), no other control
//! access right.
//!
//! Order: the simple ACE first, then the object ACEs in ascending octet
//! order of their encoding — the [MS-ADTS] 6.1.3.1 ordering rules 2-4 ("Deny
//! ACEs come before Allow ACEs"; "Regular ACEs come before object ACEs";
//! "ordered lexicographically") for an all-allow, all-explicit ACL.
//!
//! Spec: docs/51 §10 (R51-19); A-76 (Q-294 (a)); A-84 (Q-335, Q-336);
//! [MS-DTYP] v20241119 2.4.2.4, 2.4.4.1, 2.4.4.2, 2.4.4.3, 2.4.5, 2.4.6,
//! 2.5.3.1.1; [MS-ADTS] v20261026 3.1.1.3.1.5.1, 5.1.3.2, 5.1.3.3, 6.1.1.2.7.52,
//! 6.1.3 items 1, 2.1, 5, 7, 6.1.3.1; docs/53 R53-1, §5.6 step 4, §10 (K9);
//! crates/pdp decide.rs (`desired_right`).

use directory_admin::{USER_CHANGE_PASSWORD, USER_FORCE_CHANGE_PASSWORD};
use dtyp::{
    ace_flags, AccessMask, Ace, Acl, Control, Guid, MaskSidAce, ObjectAce, SecurityDescriptor, Sid,
    ACL_REVISION_DS, SECURITY_NT_AUTHORITY,
};
use pdp::access_check::rights::{
    RIGHT_DELETE, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_CREATE_CHILD, RIGHT_DS_LIST_CONTENTS,
    RIGHT_DS_READ_PROPERTY, RIGHT_DS_WRITE_PROPERTY,
};

use crate::ids::SchemaIds;

/// The mask of the root's simple ACE: read every attribute (RP), list the
/// children (LC), delete the object (DE).
/// Spec: [MS-ADTS] 5.1.3.2 (RP "If ObjectType does not contain a GUID, the
/// ACE controls the right to read all attributes of the object"; LC; DE);
/// crates/pdp `desired_right` (`DirRead` None ⇒ RP; `DirList` ⇒ LC;
/// `DirDelete` ⇒ RIGHT_DELETE).
pub const ROOT_OBJECT_RIGHTS: u32 = RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_DELETE;

/// The AceFlags of every root ACE: inheritable by container children
/// (every directory object), effective on the root, nothing else.
/// Spec: [MS-DTYP] 2.4.4.1 (CONTAINER_INHERIT_ACE 0x02); [MS-ADTS] 6.1.3
/// item 5.3; A-84 (no INHERIT_ONLY_ACE).
pub const ROOT_ACE_FLAGS: u8 = ace_flags::CONTAINER_INHERIT_ACE;

/// The SubAuthority of the well-known SID PRINCIPAL_SELF, `S-1-5-10`.
/// Spec: [MS-DTYP] 2.4.2.4 ("PRINCIPAL_SELF S-1-5-10"); [MS-ADTS] 5.1.3.3
/// ("identified by the fixed SID value of S-1-5-10").
pub const PRINCIPAL_SELF_RID: u32 = 10;

/// PRINCIPAL_SELF, `S-1-5-10` (NT AUTHORITY, one SubAuthority).
/// Spec: [MS-DTYP] 2.4.2.4.
///
/// # Errors
/// `dtyp::Error` if the SID does not form (it always does — a fixed shape).
pub(crate) fn principal_self() -> Result<Sid, dtyp::Error> {
    Sid::new(SECURITY_NT_AUTHORITY, &[PRINCIPAL_SELF_RID])
}

/// One explicit, inheritable object ACE of the root.
/// Spec: [MS-DTYP] 2.4.4.3 (ObjectType "identifies a property set,
/// property, extended right, or type of child object. The purpose of this
/// GUID depends on the user rights specified in the Mask field";
/// InheritedObjectType absent ⇒ "all types of child objects can inherit the
/// ACE").
fn object_allow(mask: u32, object_type: Guid, trustee: Sid) -> Ace {
    Ace::AccessAllowedObject(ObjectAce {
        ace_flags: ROOT_ACE_FLAGS,
        mask: AccessMask(mask),
        object_type: Some(object_type),
        inherited_object_type: None,
        sid: trustee,
    })
}

/// The domain root's security descriptor (module documentation).
///
/// # Errors
/// `dtyp::Error` if the descriptor does not validate (it always does: the
/// inputs are fixed shapes) — the caller fails closed.
///
/// Spec: docs/51 §10; A-76; A-84; [MS-DTYP] 2.4.4.1-2.4.4.3, 2.4.5,
/// 2.4.6; [MS-ADTS] 5.1.3.2, 6.1.3, 6.1.3.1.
pub(crate) fn domain_root_descriptor(
    tier0_group: Sid,
    ids: &SchemaIds,
) -> Result<SecurityDescriptor, dtyp::Error> {
    let mut object_aces = vec![
        object_allow(RIGHT_DS_CREATE_CHILD, ids.user.guid, tier0_group),
        object_allow(RIGHT_DS_CREATE_CHILD, ids.computer.guid, tier0_group),
        object_allow(RIGHT_DS_CREATE_CHILD, ids.group.guid, tier0_group),
        object_allow(
            RIGHT_DS_CREATE_CHILD,
            ids.organizational_unit.guid,
            tier0_group,
        ),
        object_allow(RIGHT_DS_CREATE_CHILD, ids.container.guid, tier0_group),
        object_allow(RIGHT_DS_WRITE_PROPERTY, ids.uac_guid, tier0_group),
        object_allow(
            RIGHT_DS_WRITE_PROPERTY,
            ids.account_expires_guid,
            tier0_group,
        ),
        object_allow(RIGHT_DS_WRITE_PROPERTY, ids.member_guid, tier0_group),
        object_allow(
            RIGHT_DS_CONTROL_ACCESS,
            USER_FORCE_CHANGE_PASSWORD,
            tier0_group,
        ),
        // Row 11 (task K9; module documentation): User-Change-Password for
        // PRINCIPAL_SELF, effective on user objects only.
        // Spec: [MS-ADTS] 3.1.1.3.1.5.1, 6.1.1.2.7.52, 5.1.3.3; [MS-DTYP]
        // 2.4.2.4, 2.4.4.3 (InheritedObjectType); docs/53 §5.6 step 4.
        Ace::AccessAllowedObject(ObjectAce {
            ace_flags: ROOT_ACE_FLAGS,
            mask: AccessMask(RIGHT_DS_CONTROL_ACCESS),
            object_type: Some(USER_CHANGE_PASSWORD),
            inherited_object_type: Some(ids.user.guid),
            sid: principal_self()?,
        }),
    ];
    // [MS-ADTS] 6.1.3.1 rule 4: "ordered lexicographically (that is, based
    // on octet string comparison rules)" within the object-ACE group.
    let mut keyed = Vec::with_capacity(object_aces.len());
    for ace in object_aces.drain(..) {
        keyed.push((ace.encode()?, ace));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut aces = Vec::with_capacity(keyed.len() + 1);
    // Rule 3: "Regular ACEs come before object ACEs."
    aces.push(Ace::AccessAllowed(MaskSidAce {
        ace_flags: ROOT_ACE_FLAGS,
        mask: AccessMask(ROOT_OBJECT_RIGHTS),
        sid: tier0_group,
    }));
    aces.extend(keyed.into_iter().map(|(_, ace)| ace));
    let sd = SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT),
        owner_sid: Some(tier0_group),
        group_sid: Some(tier0_group),
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces,
        }),
    };
    sd.validate()?;
    Ok(sd)
}
