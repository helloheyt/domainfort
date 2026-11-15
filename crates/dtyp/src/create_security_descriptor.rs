//! CreateSecurityDescriptor — the security descriptor of a new object,
//! computed from its parent's by inheritance.
//!
//! Spec: [MS-DTYP] 2.5.3.4 (introduction and the notes under Figure 11),
//! 2.5.3.4.1 CreateSecurityDescriptor, 2.5.3.4.2 ComputeACL, 2.5.3.4.3
//! ContainsInheritableACEs, 2.5.3.4.4 ComputeInheritedACLfromParent (with its
//! flag table and the paragraph after it), 2.5.3.4.7 PostProcessACL; 2.4.4.1
//! (the inheritance AceFlags), 2.4.4.3 (InheritedObjectType), 2.4.2.4 and
//! 2.4.1 (CREATOR_OWNER S-1-3-0, CREATOR_GROUP S-1-3-1), 2.5.2 (Token:
//! OwnerIndex, PrimaryGroup, DefaultDACL), 2.4.6 (Control: SR, DP, SP);
//! [MS-ADTS] 6.1.3 items 4 and 5 (the inputs Active Directory passes),
//! 5.1.3.2 (the directory access rights the generic mapping names).
//!
//! # What is built
//!
//! [`create_security_descriptor`] transcribes the 2.5.3.4.1 pseudocode with
//! **CreatorDescriptor = NULL** — project decision A-76 (Q-294): a new
//! directory object gets its parent's inheritable ACEs and nothing else, and
//! its OWNER / GROUP come from the requester's [`Token`]. The branches of
//! 2.5.3.4.2 that need a CreatorACL (and with them 2.5.3.4.5
//! ComputeInheritedACLfromCreator and 2.5.3.4.6 PreProcessACLfromCreator) are
//! not built: a `Some` creator descriptor is refused
//! ([`Error::CreatorDescriptorNotSupported`]). Q-336 records why (the text of
//! those branches has defects of its own).
//!
//! With CreatorDescriptor NULL the pseudocode reduces to:
//!
//! | Spec step | Here |
//! |---|---|
//! | 2.5.3.4.1 Step 1 (Owner), Step 2 (Group) | [`create_security_descriptor`] |
//! | 2.5.3.4.1 Step 3 / Step 4 → ComputeACL (COMPUTE_DACL / COMPUTE_SACL) | `compute_acl` |
//! | 2.5.3.4.3 ContainsInheritableACEs | `contains_inheritable_aces` |
//! | 2.5.3.4.2, parent has inheritable ACEs, "CreatorACL is not present" | `compute_inherited_acl_from_parent` then `post_process_acl` (CopyInheritedAces) |
//! | 2.5.3.4.2, no inheritable ACEs, "CreatorACL = NULL" | Token.DefaultDACL (DACL) / NULL (SACL), then `post_process_acl` (CopyAllAces) |
//! | 2.5.3.4.4 ComputeInheritedACLfromParent | `compute_inherited_acl_from_parent` |
//! | 2.5.3.4.7 PostProcessACL | `post_process_acl` / `post_process_ace` |
//!
//! The AutoInheritFlags DACL_AUTO_INHERIT, SACL_AUTO_INHERIT and
//! DEFAULT_DESCRIPTOR_FOR_OBJECT are tested by 2.5.3.4.2 only in the
//! CreatorACL-present branches, so here they have no effect, and
//! ComputedControl stays NULL (no DI / SI bit is ever set).
//!
//! # Active Directory inputs ([MS-ADTS] 6.1.3)
//!
//! For a directory object the caller passes what [MS-ADTS] 6.1.3 item 5
//! says: `is_container_object` **TRUE always** (item 5.3); the
//! [`GenericMapping::ACTIVE_DIRECTORY`] table (item 5.6); as `object_types`,
//! the GUID of the most specific structural objectClass and of every dynamic
//! auxiliary class (item 4); the parent's SD (item 5.1; NULL for an NC root).
//! Item 5.2 (CreatorDescriptor = the defaulted SD of 6.1.3.6 / 6.1.3.7) is
//! replaced by NULL by decision A-76. Item 7 ("NULL DACLs are disallowed") is
//! the caller's check: this function returns a descriptor without a DACL when
//! the parent has no inheritable DACL ACE and `Token.default_dacl` is `None`
//! (2.5.3.4.2), and the access check denies everything on it (A-13).
//!
//! # Where the pseudocode and other text disagree
//!
//! The pseudocode is followed as written except where the main session
//! decided otherwise (decision A-84 on Q-335 / Q-336). Each such place is
//! marked `A-84`, `Q-335` or `Q-336` at its `// Spec:` comment:
//!
//! - **A-84 (Q-335 option (b)):** the first test of 2.5.3.4.4 ("IF
//!   ACE.AceFlags contains INHERIT_ONLY_ACE THEN CONTINUE") is not applied —
//!   whether an ACE is inherited, and whether as an effective ACE, is decided
//!   by CI / OI / NP and the InheritedObjectType match, as the paragraph after
//!   the 2.5.3.4.4 pseudocode, its flag table and [MS-ADTS] 6.1.3 items 2 and 4
//!   say. With the test, every inherit-only copy would be skipped one
//!   generation later and no ACE would be effective more than one level down.
//! - **A-84, PostProcessACL (2.5.3.4.7):** only **effective** ACEs are
//!   processed: CREATOR_OWNER / CREATOR_GROUP are substituted, the four
//!   generic rights (GENERIC_ALL included) are mapped and their bits cleared
//!   (2.4.3; [MS-ADTS] 5.1.3.2). Inherit-only copies keep the CREATOR_*
//!   placeholder ([MS-ADTS] 6.1.3 item 6) and the generic bits (2.5.3.4.4,
//!   closing paragraph).
//! - **Q-336 (readings, accepted as built):** "ACE.ObjectGUID" is read as
//!   InheritedObjectType, absent ⇒ every child type (2.4.4.3); a NULL ACL
//!   stays NULL through PostProcessACL; the computed ACL keeps its source's
//!   AclRevision; the CASE of 2.5.3.4.4 has no arm for audit ACEs, so they
//!   get no effective copy.
//!
//! # Fail closed (docs/CLEAN-ROOM.md) and bounds
//!
//! - DELIBERATE: an inheritable ACE of a type this crate keeps as
//!   [`Ace::Unsupported`] cannot be substituted or mapped (2.5.3.4.7 needs its
//!   Sid and Mask), and silently dropping it could drop a deny; it is refused
//!   ([`Error::UnsupportedAceInComputedAcl`]) instead.
//! - An OWNER or GROUP that would be absent is refused
//!   ([`Error::NewDescriptorOwnerAbsent`] / [`Error::NewDescriptorGroupAbsent`]).
//! - The inputs are bounded before anything is built: the parent descriptor
//!   and the token's default DACL must encode (each ACL ≤ 65535 bytes,
//!   [MS-DTYP] 2.4.5), so the working lists hold at most twice the parent's
//!   ACEs. The result is validated by the canonical encoder; an ACL that
//!   inheritance makes larger than AclSize can express is
//!   [`Error::AclTooLarge`] — never truncated.
//! - No ACE is ever added for the owner (A-21): a computed effective ACE
//!   names the owner only if its source ACE (the parent's, or
//!   Token.DefaultDACL's) named that SID or CREATOR_OWNER (2.5.3.4.7).
//!
//! The output order is the pseudocode's: the effective copies in parent
//! order, then the inherit-only copies in parent order (2.5.3.4.4 "RETURN
//! concatenation of ExplicitACL and InheritableACL"). [MS-ADTS] 6.1.3.1
//! sorting is not applied (Q-336).

use crate::access_mask::AccessMask;
use crate::ace::{ace_flags, Ace};
use crate::acl::Acl;
use crate::error::{Error, Result};
use crate::guid::Guid;
use crate::security_descriptor::{Control, SecurityDescriptor};
use crate::sid::{Sid, CREATOR_SID_AUTHORITY};

/// AutoInheritFlags. Spec: [MS-DTYP] 2.5.3.4.1 (parameter list).
///
/// The spec gives these as named flags without numeric values, so they are
/// booleans here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AutoInheritFlags {
    /// DACL_AUTO_INHERIT. No effect without a CreatorDescriptor: 2.5.3.4.2
    /// tests it only when a CreatorACL is present.
    pub dacl_auto_inherit: bool,
    /// SACL_AUTO_INHERIT. No effect without a CreatorDescriptor (as above).
    pub sacl_auto_inherit: bool,
    /// DEFAULT_DESCRIPTOR_FOR_OBJECT. No effect without a CreatorDescriptor
    /// (as above).
    pub default_descriptor_for_object: bool,
    /// DEFAULT_OWNER_FROM_PARENT: the new Owner is the parent's Owner instead
    /// of Token.Sids[Token.OwnerIndex]. Spec: 2.5.3.4.1 Step 1.
    pub default_owner_from_parent: bool,
    /// DEFAULT_GROUP_FROM_PARENT: the new Group is the parent's Group instead
    /// of Token.Sids[Token.PrimaryGroup]. Spec: 2.5.3.4.1 Step 2.
    pub default_group_from_parent: bool,
}

/// GenericMapping: "Mapping of generic permissions to resource
/// manager-specific permissions supplied by the caller".
///
/// Spec: [MS-DTYP] 2.5.3.4.1, 2.5.3.4.7 (GenericMapping.GenericRead /
/// .GenericWrite / .GenericExecute), 2.4.3 (GA is translated too);
/// [MS-ADTS] 6.1.3 item 5.6 (the four-row table, GENERIC_ALL_MAPPING
/// included). Each value is added to an **effective** computed ACE whose mask
/// contains the generic right, and the generic bits are then cleared
/// (decision A-84, Q-336 item 2); inherit-only copies keep their generic bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenericMapping {
    /// GenericRead: for GENERIC_READ.
    pub generic_read: u32,
    /// GenericWrite: for GENERIC_WRITE.
    pub generic_write: u32,
    /// GenericExecute: for GENERIC_EXECUTE.
    pub generic_execute: u32,
    /// GenericAll: for GENERIC_ALL — GENERIC_ALL_MAPPING of [MS-ADTS] 6.1.3
    /// item 5.6; not named by 2.5.3.4.7, applied per 2.4.3 (A-84).
    pub generic_all: u32,
}

impl GenericMapping {
    /// "The following mapping table is used for all Active Directory SD
    /// operations" — [MS-ADTS] 6.1.3 item 5.6. The right names are those of
    /// [MS-ADTS] 5.1.3.2, whose values equal the [`AccessMask`] constants
    /// used here: RC = READ_CONTROL 0x00020000, LC = 0x00000004
    /// (DIRECTORY_OBJECT_LIST_CHILDREN), RP = 0x00000010, LO = 0x00000080,
    /// VW = 0x00000008 (ADS_RIGHT_DS_SELF), WP = 0x00000020, DE = 0x00010000,
    /// WD = 0x00040000, WO = 0x00080000, CC = 0x00000001, DC = 0x00000002,
    /// DT = 0x00000040, CR = 0x00000100.
    pub const ACTIVE_DIRECTORY: GenericMapping = GenericMapping {
        // GENERIC_READ_MAPPING = RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS
        // | RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_OBJECT.
        generic_read: AccessMask::READ_CONTROL
            | AccessMask::DIRECTORY_OBJECT_LIST_CHILDREN
            | AccessMask::ADS_RIGHT_DS_READ_PROP
            | AccessMask::DIRECTORY_OBJECT_LIST_OBJECT,
        // GENERIC_WRITE_MAPPING = RIGHT_READ_CONTROL |
        // RIGHT_DS_WRITE_PROPERTY_EXTENDED | RIGHT_DS_WRITE_PROPERTY.
        generic_write: AccessMask::READ_CONTROL
            | AccessMask::ADS_RIGHT_DS_SELF
            | AccessMask::ADS_RIGHT_DS_WRITE_PROP,
        // GENERIC_EXECUTE_MAPPING = RIGHT_READ_CONTROL | RIGHT_DS_LIST_CONTENTS.
        generic_execute: AccessMask::READ_CONTROL | AccessMask::DIRECTORY_OBJECT_LIST_CHILDREN,
        // GENERIC_ALL_MAPPING = RIGHT_DELETE | RIGHT_READ_CONTROL |
        // RIGHT_WRITE_DAC | RIGHT_WRITE_OWNER | RIGHT_DS_CREATE_CHILD |
        // RIGHT_DS_DELETE_CHILD | RIGHT_DS_DELETE_TREE | RIGHT_DS_READ_PROPERTY
        // | RIGHT_DS_WRITE_PROPERTY | RIGHT_DS_LIST_CONTENTS |
        // RIGHT_DS_LIST_OBJECT | RIGHT_DS_CONTROL_ACCESS |
        // RIGHT_DS_WRITE_PROPERTY_EXTENDED.
        generic_all: AccessMask::DELETE
            | AccessMask::READ_CONTROL
            | AccessMask::WRITE_DACL
            | AccessMask::WRITE_OWNER
            | AccessMask::ADS_RIGHT_DS_CREATE_CHILD
            | AccessMask::ADS_RIGHT_DS_DELETE_CHILD
            | AccessMask::DIRECTORY_OBJECT_DELETE_TREE
            | AccessMask::ADS_RIGHT_DS_READ_PROP
            | AccessMask::ADS_RIGHT_DS_WRITE_PROP
            | AccessMask::DIRECTORY_OBJECT_LIST_CHILDREN
            | AccessMask::DIRECTORY_OBJECT_LIST_OBJECT
            | AccessMask::ADS_RIGHT_DS_CONTROL_ACCESS
            | AccessMask::ADS_RIGHT_DS_SELF,
    };
}

/// The parts of the Token (authorization context) that CreateSecurityDescriptor
/// reads. Spec: [MS-DTYP] 2.5.2 (Sids[], OwnerIndex, PrimaryGroup,
/// DefaultDACL); 2.5.3.4.1 Steps 1-2; 2.5.3.4.2 ("Set TmpACL to
/// Token.DefaultDACL").
///
/// For a directory object the requester's token is used ([MS-ADTS] 6.1.3
/// item 5.5); by decision A-76 the owner is the requester's SID, because the
/// default administrators group is undefined ([MS-ADTS] 6.1.3.7, 6.1.3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Token.Sids[Token.OwnerIndex]: "which SID to assign as the owner for
    /// new objects". Spec: [MS-DTYP] 2.5.2.
    pub owner: Sid,
    /// Token.Sids[Token.PrimaryGroup]: "which SID to use as the primary group
    /// of the user". Spec: [MS-DTYP] 2.5.2.
    pub primary_group: Sid,
    /// Token.DefaultDACL: "A DACL ... that can be applied to new objects when
    /// there is no parent security descriptor for inheritance and no explicit
    /// new security descriptor was supplied". `None` = no default DACL.
    /// Spec: [MS-DTYP] 2.5.2.
    pub default_dacl: Option<Acl>,
}

/// ComputeType. Spec: [MS-DTYP] 2.5.3.4.2 ("Enumeration of COMPUTE_DACL and
/// COMPUTE_SACL"; the body writes DACL_COMPUTE / SACL_COMPUTE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComputeType {
    ComputeDacl,
    ComputeSacl,
}

/// CopyFilter. Spec: [MS-DTYP] 2.5.3.4.7. The third value, CopyExplicitAces,
/// is never passed by ComputeACL (2.5.3.4.2) and so is not represented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyFilter {
    CopyAllAces,
    CopyInheritedAces,
}

/// CreateSecurityDescriptor with CreatorDescriptor = NULL: the security
/// descriptor of a new object, from its parent's descriptor and the creator's
/// token.
///
/// Parameters, as [MS-DTYP] 2.5.3.4.1 names them:
/// - `parent_descriptor` — ParentDescriptor; `None` if the object has no
///   parent (an NC root, [MS-ADTS] 6.1.3 item 5.1).
/// - `creator_descriptor` — CreatorDescriptor; must be `None` (A-76).
///   `Some` ⇒ [`Error::CreatorDescriptorNotSupported`].
/// - `is_container_object` — IsContainerObject; `true` for every directory
///   object ([MS-ADTS] 6.1.3 item 5.3).
/// - `object_types` — ObjectTypes; `None` when the object has no GUID
///   ("this field MUST be set to null").
/// - `auto_inherit_flags` — AutoInheritFlags.
/// - `token` — Token.
/// - `generic_mapping` — GenericMapping.
///
/// Returns NewDescriptor, in a form the canonical encoder accepts
/// ([`SecurityDescriptor::encode`]).
///
/// Spec: [MS-DTYP] 2.5.3.4.1.
pub fn create_security_descriptor(
    parent_descriptor: Option<&SecurityDescriptor>,
    creator_descriptor: Option<&SecurityDescriptor>,
    is_container_object: bool,
    object_types: Option<&[Guid]>,
    auto_inherit_flags: AutoInheritFlags,
    token: &Token,
    generic_mapping: &GenericMapping,
) -> Result<SecurityDescriptor> {
    // A-76 (Q-294): CreatorDescriptor is NULL; the creator-present branches of
    // 2.5.3.4.2 are not built (Q-336). Fail closed on anything else.
    if creator_descriptor.is_some() {
        return Err(Error::CreatorDescriptorNotSupported);
    }
    // Bound the inputs before building anything from them (docs/CLEAN-ROOM.md): the
    // parent must be an encodable descriptor (every ACL <= 65535 bytes,
    // [MS-DTYP] 2.4.5; flags consistent, 2.4.6), and so must the default DACL.
    if let Some(parent) = parent_descriptor {
        parent.encoded_len()?;
    }
    if let Some(default_dacl) = &token.default_dacl {
        default_dacl.encoded_len()?;
        default_dacl.check_dacl()?;
    }

    // Step 1: Compute the Owner field. "IF CreatorDescriptor.Owner is NULL"
    // holds (no CreatorDescriptor). Spec: [MS-DTYP] 2.5.3.4.1 Step 1; <96>.
    let owner = if auto_inherit_flags.default_owner_from_parent {
        // "Set NewDescriptor.Owner to ParentDescriptor.Owner". An absent
        // owner is refused ([MS-ADTS] 6.1.3 item 1: "The owner SID cannot be
        // NULL"; fail closed).
        parent_descriptor
            .and_then(|parent| parent.owner_sid)
            .ok_or(Error::NewDescriptorOwnerAbsent)?
    } else {
        // "Set NewDescriptor.Owner to Token.SIDs[Token.OwnerIndex]".
        token.owner
    };

    // Step 2: Compute the Group field. Spec: [MS-DTYP] 2.5.3.4.1 Step 2; <96>.
    let group = if auto_inherit_flags.default_group_from_parent {
        // "Set NewDescriptor.Group to ParentDescriptor.Group". An absent
        // group is refused (fail closed; the codec would need GD set).
        parent_descriptor
            .and_then(|parent| parent.group_sid)
            .ok_or(Error::NewDescriptorGroupAbsent)?
    } else {
        // "Set NewDescriptor.Group to Token.SIDs[Token.PrimaryGroup]".
        token.primary_group
    };

    // Step 3: Compute the DACL — ComputeACL with ComputeType COMPUTE_DACL,
    // ParentACL = ParentDescriptor.DACL. Spec: [MS-DTYP] 2.5.3.4.1 Step 3.
    let (new_dacl, dacl_control) = compute_acl(
        ComputeType::ComputeDacl,
        parent_descriptor.and_then(|parent| parent.dacl.as_ref()),
        is_container_object,
        object_types,
        generic_mapping,
        &owner,
        &group,
        token,
    )?;

    // Step 4: Compute the SACL — ComputeACL with ComputeType COMPUTE_SACL,
    // ParentACL = ParentDescriptor.SACL. Spec: [MS-DTYP] 2.5.3.4.1 Step 4.
    let (new_sacl, sacl_control) = compute_acl(
        ComputeType::ComputeSacl,
        parent_descriptor.and_then(|parent| parent.sacl.as_ref()),
        is_container_object,
        object_types,
        generic_mapping,
        &owner,
        &group,
        token,
    )?;

    // "Set NewDescriptor.Control to NewControl", then "(NewDescriptor.Control
    // OR NewControl)" (Spec: 2.5.3.4.1 Steps 3-4). The representation bits
    // come from [MS-DTYP] 2.4.6: SR "MUST be set" in self-relative form; DP /
    // SP are set exactly when the DACL / SACL is present. OD / GD stay clear:
    // owner and group are always present here.
    let mut control = Control::SELF_RELATIVE | dacl_control.0 | sacl_control.0;
    if new_dacl.is_some() {
        control |= Control::DACL_PRESENT;
    }
    if new_sacl.is_some() {
        control |= Control::SACL_PRESENT;
    }
    let new_descriptor = SecurityDescriptor {
        // No resource manager control bits (RM clear). Spec: [MS-DTYP] 2.4.6.
        sbz1: 0,
        control: Control(control),
        owner_sid: Some(owner),
        group_sid: Some(group),
        sacl: new_sacl,
        dacl: new_dacl,
    };
    // The result must encode within the dtyp bounds — an ACL that inheritance
    // made larger than AclSize can hold is an error (Error::AclTooLarge),
    // never truncated; DACL / SACL type rules are re-checked. Spec: [MS-DTYP]
    // 2.4.5, 2.4.6.
    new_descriptor.encoded_len()?;
    Ok(new_descriptor)
}

/// ComputeACL, for CreatorACL NULL (the only case built). Returns the
/// computed ACL and ComputedControl.
///
/// Spec: [MS-DTYP] 2.5.3.4.2. ComputedControl is only ever assigned in the
/// CreatorACL-present branches, so it stays NULL here.
#[allow(clippy::too_many_arguments)] // the parameter list of 2.5.3.4.2
fn compute_acl(
    compute_type: ComputeType,
    parent_acl: Option<&Acl>,
    is_container_object: bool,
    object_types: Option<&[Guid]>,
    generic_mapping: &GenericMapping,
    owner: &Sid,
    group: &Sid,
    token: &Token,
) -> Result<(Option<Acl>, Control)> {
    // "Set ComputedControl to NULL".
    let computed_control = Control(0);

    // "CALL ContainsInheritableACEs WITH ParentACL RETURNING
    // ParentHasInheritableACEs" (a NULL ParentACL has none, so the parent ACL
    // is present whenever this is TRUE).
    let parent_has_inheritable_aces = contains_inheritable_aces(parent_acl);
    if let (true, Some(acl)) = (parent_has_inheritable_aces, parent_acl) {
        // "IF (CreatorACL is not present) OR ..." — CreatorACL is never
        // present here, so: "Use only the inherited ACEs from the parent".
        let next_acl = compute_inherited_acl_from_parent(acl, is_container_object, object_types)?;
        let final_acl = post_process_acl(
            Some(next_acl),
            CopyFilter::CopyInheritedAces,
            owner,
            group,
            generic_mapping,
        )?;
        return Ok((final_acl, computed_control));
    }

    // "ELSE // ParentACL does not contain inheritable ACEs"; "IF CreatorACL =
    // NULL THEN": the DACL takes Token.DefaultDACL; "No default for SACL;
    // left as NULL".
    let tmp_acl = match compute_type {
        ComputeType::ComputeDacl => token.default_dacl.clone(),
        ComputeType::ComputeSacl => None,
    };
    let processed_acl = post_process_acl(
        tmp_acl,
        CopyFilter::CopyAllAces,
        owner,
        group,
        generic_mapping,
    )?;
    Ok((processed_acl, computed_control))
}

/// ContainsInheritableACEs: TRUE if any ACE has CONTAINER_INHERIT_ACE or
/// OBJECT_INHERIT_ACE. A NULL ACL contains none.
///
/// Spec: [MS-DTYP] 2.5.3.4.3.
fn contains_inheritable_aces(acl: Option<&Acl>) -> bool {
    acl.is_some_and(|acl| acl.aces.iter().any(|ace| is_inheritable(ace.ace_flags())))
}

/// `(ACE.AceFlags contains CONTAINER_INHERIT_ACE) OR (ACE.AceFlags contains
/// OBJECT_INHERIT_ACE)`. Spec: [MS-DTYP] 2.5.3.4.3, 2.5.3.4.4.
fn is_inheritable(flags: u8) -> bool {
    flags & (ace_flags::CONTAINER_INHERIT_ACE | ace_flags::OBJECT_INHERIT_ACE) != 0
}

/// ComputeInheritedACLfromParent: the effective ACEs the new object inherits
/// (ExplicitACL), followed by — for a container — the inherit-only copies it
/// passes on (InheritableACL).
///
/// Spec: [MS-DTYP] 2.5.3.4.4.
fn compute_inherited_acl_from_parent(
    acl: &Acl,
    is_container_object: bool,
    object_types: Option<&[Guid]>,
) -> Result<Acl> {
    // DELIBERATE (fail closed, docs/CLEAN-ROOM.md): an inheritable ACE this crate
    // does not interpret cannot be substituted or mapped (2.5.3.4.7 needs its
    // Sid and Mask), and dropping it could drop a deny. Refuse it.
    if acl
        .aces
        .iter()
        .any(|ace| matches!(ace, Ace::Unsupported(_)) && is_inheritable(ace.ace_flags()))
    {
        return Err(Error::UnsupportedAceInComputedAcl);
    }

    // "Initialize ExplicitACL to Empty ACL". Bounded: at most the parent's ACE
    // count (the parent encodes, so <= 65535 / 4 ACEs).
    let mut explicit_acl: Vec<Ace> = Vec::new();
    for ace in &acl.aces {
        let flags = ace.ace_flags();
        // The pseudocode's first test, "IF ACE.AceFlags contains
        // INHERIT_ONLY_ACE THEN CONTINUE", is NOT applied — decision A-84
        // (Q-335, option (b)): with it, every inherit-only copy made below
        // would be skipped one generation later, so no ACE would be effective
        // more than one level down. Spec: [MS-DTYP] 2.5.3.4.4, the paragraph
        // after the pseudocode ("IO and ID do not play a part when it comes to
        // making decisions about inheritance ... An ACE that has the IO flag
        // can be inherited, but the decision is based on other flags"), and
        // its flag table (decided by CI / OI / NP alone); [MS-ADTS] 6.1.3
        // item 2 ("both applicable and nonapplicable inheritable ACEs") and
        // item 4 (INHERIT_ONLY_ACE marks effectiveness by the objectClass
        // match); also [MS-DTYP] 2.4.4.1 ("Both effective and inherit-only
        // ACEs can be inherited").
        //
        // "IF (((ACE.AceFlags contains CONTAINER_INHERIT_ACE) AND
        // (IsContainerObject = TRUE)) OR ((ACE.AceFlags contains
        // OBJECT_INHERIT_ACE) AND (IsContainerObject = FALSE)))".
        let applies = (flags & ace_flags::CONTAINER_INHERIT_ACE != 0 && is_container_object)
            || (flags & ace_flags::OBJECT_INHERIT_ACE != 0 && !is_container_object);
        if !applies {
            continue;
        }
        // "CASE ACE.Type OF".
        let copy = match ace {
            // "ACCESS_ALLOWED_ACE_TYPE: ACCESS_DENIED_ACE_TYPE:" — copied.
            Ace::AccessAllowed(_) | Ace::AccessDenied(_) => true,
            // "ACCESS_ALLOWED_OBJECT_ACE_TYPE: ACCESS_DENIED_OBJECT_ACE_TYPE:
            // IF (ObjectTypes contains ACE.ObjectGUID)" — ObjectGUID read as
            // InheritedObjectType, absent ⇒ every child type (2.4.4.3) —
            // Q-336.
            Ace::AccessAllowedObject(object_ace) | Ace::AccessDeniedObject(object_ace) => {
                object_types_contain(object_types, object_ace.inherited_object_type)
            }
            // No CASE arm for the audit types: no effective copy (literal;
            // Q-336). Unsupported types were refused above.
            Ace::SystemAudit(_) | Ace::SystemAuditObject { .. } | Ace::Unsupported(_) => false,
        };
        if copy {
            // "Copy ACE to NewACE; Clear NewACE.AceFlags – no flags set;
            // NewACE.AceFlags = INHERITED_ACE; Append NewACE to ExplicitACL".
            explicit_acl.push(with_ace_flags(ace, ace_flags::INHERITED_ACE));
        }
    }

    // "Initialize InheritableACL to Empty ACL"; "IF (IsContainerObject =
    // TRUE)". Bounded as above.
    let mut inheritable_acl: Vec<Ace> = Vec::new();
    if is_container_object {
        for ace in &acl.aces {
            let flags = ace.ace_flags();
            // "IF ACE.AceFlags does not contain NO_PROPAGATE_INHERIT_ACE THEN
            // IF ((ACE.AceFlags contains CONTAINER_INHERIT_ACE) OR
            // (ACE.AceFlags contains OBJECT_INHERIT_ACE))".
            if flags & ace_flags::NO_PROPAGATE_INHERIT_ACE == 0 && is_inheritable(flags) {
                // "Set NewACE to ACE; Add INHERITED_ACE to NewACE.AceFlags;
                // Add INHERIT_ONLY_ACE to NewACE.AceFlags; Append NewACE to
                // InheritableACL".
                inheritable_acl.push(with_ace_flags(
                    ace,
                    flags | ace_flags::INHERITED_ACE | ace_flags::INHERIT_ONLY_ACE,
                ));
            }
        }
    }

    // "RETURN concatenation of ExplicitACL and InheritableACL". The ACE types
    // are a subset of the parent ACL's, so its AclRevision permits them
    // ([MS-DTYP] 2.4.5) — Q-336.
    explicit_acl.extend(inheritable_acl);
    Ok(Acl {
        acl_revision: acl.acl_revision,
        aces: explicit_acl,
    })
}

/// `ObjectTypes contains <guid>`, with the reading of Q-336: an absent
/// InheritedObjectType means "all types of child objects can inherit the
/// ACE" ([MS-DTYP] 2.4.4.3, ACE_INHERITED_OBJECT_TYPE_PRESENT); a NULL
/// ObjectTypes (object without a GUID, 2.5.3.4.1) contains no GUID.
fn object_types_contain(
    object_types: Option<&[Guid]>,
    inherited_object_type: Option<Guid>,
) -> bool {
    match inherited_object_type {
        None => true,
        Some(guid) => object_types.is_some_and(|types| types.contains(&guid)),
    }
}

/// A copy of `ace` with its AceFlags replaced. Spec: [MS-DTYP] 2.4.4.1.
fn with_ace_flags(ace: &Ace, flags: u8) -> Ace {
    let mut copy = ace.clone();
    match &mut copy {
        Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => a.ace_flags = flags,
        Ace::AccessAllowedObject(a)
        | Ace::AccessDeniedObject(a)
        | Ace::SystemAuditObject { ace: a, .. } => a.ace_flags = flags,
        Ace::Unsupported(u) => u.ace_flags = flags,
    }
    copy
}

/// PostProcessACL: keep the ACEs the filter selects; in each **effective**
/// one, substitute CREATOR_OWNER / CREATOR_GROUP and map the generic rights
/// (decision A-84, see `post_process_ace`).
///
/// A NULL ACL stays NULL (the SACL is "left as NULL", 2.5.3.4.2) — Q-336.
///
/// Spec: [MS-DTYP] 2.5.3.4.7.
fn post_process_acl(
    acl: Option<Acl>,
    copy_filter: CopyFilter,
    owner: &Sid,
    group: &Sid,
    generic_mapping: &GenericMapping,
) -> Result<Option<Acl>> {
    let Some(acl) = acl else {
        return Ok(None);
    };
    // "Initialize NewACL to Empty ACL". Bounded by the input ACL.
    let mut new_acl: Vec<Ace> = Vec::new();
    for ace in acl.aces {
        // "CASE CopyFilter OF CopyAllAces: SET CopyThisAce = TRUE;
        // CopyInheritedAces: IF (ACE.AceFlags contains INHERITED_ACE) THEN
        // SET CopyThisAce = TRUE".
        let copy_this_ace = match copy_filter {
            CopyFilter::CopyAllAces => true,
            CopyFilter::CopyInheritedAces => ace.ace_flags() & ace_flags::INHERITED_ACE != 0,
        };
        if copy_this_ace {
            // "Append NewACE to NewACL".
            new_acl.push(post_process_ace(ace, owner, group, generic_mapping)?);
        }
    }
    // The ACL keeps its AclRevision — Q-336.
    Ok(Some(Acl {
        acl_revision: acl.acl_revision,
        aces: new_acl,
    }))
}

/// The per-ACE body of PostProcessACL for a copied ACE ("Set NewACE to ACE").
///
/// Decision A-84 (Q-335, Q-336): only an **effective** ACE (INHERIT_ONLY_ACE
/// clear) is substituted and mapped. An inherit-only copy is kept exactly as
/// inherited — its CREATOR_OWNER / CREATOR_GROUP placeholder and its generic
/// bits stay — so that each later generation resolves them for its own
/// creator: otherwise an intermediate object's owner would gain the right on
/// every later descendant. Spec: [MS-ADTS] 6.1.3 item 6 ("Any CREATOR/OWNER
/// ineffective ACE has a matching effective ACE granted to the current
/// owner"); [MS-DTYP] 2.5.3.4.4, closing paragraph ("an ACE with an
/// additional IO flag with generic information and an effective-only ACE in
/// which the generic information has been mapped"); 2.4.2.4 (CREATOR_OWNER /
/// CREATOR_GROUP are placeholders replaced "When the ACE is inherited").
///
/// Spec: [MS-DTYP] 2.5.3.4.7.
fn post_process_ace(
    mut ace: Ace,
    owner: &Sid,
    group: &Sid,
    generic_mapping: &GenericMapping,
) -> Result<Ace> {
    let effective = ace.ace_flags() & ace_flags::INHERIT_ONLY_ACE == 0;
    match &mut ace {
        // Only reachable through Token.DefaultDACL (CopyAllAces): the Sid and
        // Mask of an uninterpreted ACE are not known — fail closed.
        Ace::Unsupported(_) => return Err(Error::UnsupportedAceInComputedAcl),
        _ if !effective => {}
        Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => {
            substitute_and_map(&mut a.mask, &mut a.sid, owner, group, generic_mapping);
        }
        Ace::AccessAllowedObject(a)
        | Ace::AccessDeniedObject(a)
        | Ace::SystemAuditObject { ace: a, .. } => {
            substitute_and_map(&mut a.mask, &mut a.sid, owner, group, generic_mapping);
        }
    }
    Ok(ace)
}

/// The four generic rights. Spec: [MS-DTYP] 2.4.3 (GR, GW, GX, GA).
const GENERIC_RIGHTS: u32 = AccessMask::GENERIC_READ
    | AccessMask::GENERIC_WRITE
    | AccessMask::GENERIC_EXECUTE
    | AccessMask::GENERIC_ALL;

/// On an effective ACE: "CASE ACE.Sid OF CREATOR_OWNER: NewACE.Sid = Owner;
/// CREATOR_GROUP: NewACE.Sid = Group" (2.5.3.4.7), then the generic rights
/// mapped and cleared.
///
/// Generic rights — decision A-84 (Q-336 item 2): for each of GENERIC_READ,
/// GENERIC_WRITE, GENERIC_EXECUTE **and GENERIC_ALL** present in ACE.Mask (the
/// original mask, as 2.5.3.4.7 tests it), the matching GenericMapping value is
/// added; then all four generic bits are cleared. Spec: [MS-DTYP] 2.5.3.4.7
/// (GR / GW / GX added); 2.4.3 ("When the GA bit is set in an ACE that is to
/// be attached to an object, it is translated ... During this translation,
/// the GA bit is cleared", and likewise GR, GW, GX); [MS-ADTS] 5.1.3.2 (the
/// "GENERIC" bits "are never stored in Active Directory security descriptor
/// values ... the GENERIC access bits are mapped"), 6.1.3 item 5.6 (the
/// table, GENERIC_ALL_MAPPING included).
///
/// Spec: [MS-DTYP] 2.5.3.4.7, 2.4.3; 2.4.2.4 (CREATOR_OWNER, CREATOR_GROUP).
fn substitute_and_map(
    mask: &mut AccessMask,
    sid: &mut Sid,
    owner: &Sid,
    group: &Sid,
    generic_mapping: &GenericMapping,
) {
    if is_creator_sid(sid, CREATOR_OWNER_RID) {
        *sid = *owner;
    } else if is_creator_sid(sid, CREATOR_GROUP_RID) {
        *sid = *group;
    }
    let original = mask.0;
    let mut mapped = original;
    if original & AccessMask::GENERIC_READ != 0 {
        mapped |= generic_mapping.generic_read;
    }
    if original & AccessMask::GENERIC_WRITE != 0 {
        mapped |= generic_mapping.generic_write;
    }
    if original & AccessMask::GENERIC_EXECUTE != 0 {
        mapped |= generic_mapping.generic_execute;
    }
    if original & AccessMask::GENERIC_ALL != 0 {
        mapped |= generic_mapping.generic_all;
    }
    mask.0 = mapped & !GENERIC_RIGHTS;
}

/// The last SubAuthority of CREATOR_OWNER, S-1-3-0. Spec: [MS-DTYP] 2.4.2.4.
const CREATOR_OWNER_RID: u32 = 0;
/// The last SubAuthority of CREATOR_GROUP, S-1-3-1. Spec: [MS-DTYP] 2.4.2.4.
const CREATOR_GROUP_RID: u32 = 1;

/// `true` for S-1-3-`rid`: CREATOR_SID_AUTHORITY with the one SubAuthority
/// `rid`. Spec: [MS-DTYP] 2.4.1 (CREATOR_SID_AUTHORITY {0,0,0,0,0,3}),
/// 2.4.2.4.
fn is_creator_sid(sid: &Sid, rid: u32) -> bool {
    sid.identifier_authority() == CREATOR_SID_AUTHORITY && sid.sub_authority() == [rid]
}
