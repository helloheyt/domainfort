//! Preparing a DACL for evaluation: validation, the project's stricter
//! preconditions, and normalisation of each ACE.
//!
//! A [`PreparedDacl`] can only be obtained through [`PreparedDacl::prepare`],
//! so every evaluator in this module tree runs on a DACL that has passed the
//! preconditions below.
//!
//! Preconditions (each failure ⇒ the access check denies):
//!
//! 1. Project rule 5a (docs/11 §5, D37) — DELIBERATE DEVIATION. An absent
//!    DACL (DP flag clear / no DACL) is refused. [MS-DTYP] 2.5.3.2: "No DACL
//!    in the security descriptor implies that there is no policy in place to
//!    govern access to the object; any access check will succeed"; [MS-ADTS]
//!    5.1.3.3.1-5.1.3.3.5 rule 1 likewise grants everything. This project
//!    removes that default: fail closed. (Consistent with [MS-ADTS] 6.1.3 item
//!    7, "NULL DACLs are disallowed", for descriptors a DC maintains.)
//! 2. Project rule 5b (docs/11 §5, D37) — DELIBERATE DEVIATION. Any ACE in the
//!    DACL other than the four access ACE types this crate evaluates —
//!    i.e. any `Ace::Unsupported` (callback, conditional, mandatory label,
//!    resource attribute, scoped policy, alarm, compound, ...) and any audit
//!    ACE — refuses the request, whatever its flags (inherit-only included).
//!    [MS-DTYP] 2.5.3.2 would evaluate callback ACEs (EvaluateAceCondition)
//!    and skip types it has no case for; this project fails closed instead.
//! 3. Structural validity (fail closed, D40): the descriptor passes
//!    `SecurityDescriptor::validate` ([MS-DTYP] 2.4.6, 2.4.5, 2.4.3) and
//!    every ACE type is permitted by the ACL's AclRevision ([MS-DTYP] 2.4.5).
//!
//! Normalisation (each ACE becomes a [`DaclEntry`]):
//!
//! - The mask becomes its effective AD rights: generic rights mapped, X bits
//!   dropped ([MS-ADTS] 5.1.3.2; see [`super::rights::effective_ace_rights`]).
//! - An object ACE whose ObjectType is absent is the same as the
//!   corresponding simple ACE: [MS-ADTS] 5.1.3.3.3 steps 4 and 7 ("treat the
//!   ACE type as 'Access Allowed'" / "'Access Denied'"); [MS-DTYP] 2.4.4.3 /
//!   2.4.4.5 (ObjectType "is present only if the ACE_OBJECT_TYPE_PRESENT bit is
//!   set ... Otherwise, the ObjectType field is ignored"); [MS-ADTS] 5.1.3.2
//!   ("If ObjectType does not contain a GUID, the ACE controls ..." all of
//!   that right). Both forms are therefore one entry with `object_type: None`.
//! - InheritedObjectType is not consulted: for a DC-maintained descriptor the
//!   effect of InheritedObjectType is recorded by setting INHERIT_ONLY_ACE on
//!   ineffective ACEs ([MS-ADTS] 6.1.3 item 4), and every evaluator skips
//!   inherit-only ACEs.

use dtyp::{ace_flags, acl_revision_permits, Ace, Guid, SecurityDescriptor, Sid};

use super::rights::effective_ace_rights;
use super::token::AceKind;

/// Why a DACL could not be prepared. Every variant makes the check deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaclRefusal {
    /// Rule 5a: the descriptor has no DACL (DP clear).
    AbsentDacl,
    /// Rule 5b: the DACL holds an ACE type outside the four access types.
    UnsupportedAce,
    /// The descriptor or an ACL in it is structurally invalid.
    InvalidDescriptor,
}

/// One normalised DACL entry. Spec: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaclEntry {
    /// Allow or Deny.
    pub(crate) kind: AceKind,
    /// INHERIT_ONLY_ACE is set. Spec: [MS-DTYP] 2.4.4.1.
    pub(crate) inherit_only: bool,
    /// Effective AD rights. Spec: [MS-ADTS] 5.1.3.2.
    pub(crate) mask: u32,
    /// ObjectType, if present. Spec: [MS-DTYP] 2.4.4.3, 2.4.4.5.
    pub(crate) object_type: Option<Guid>,
    /// The trustee. Spec: [MS-DTYP] 2.4.4.2-2.4.4.5.
    pub(crate) sid: Sid,
}

/// A DACL that passed the preconditions, as normalised entries in DACL order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedDacl {
    entries: Vec<DaclEntry>,
}

impl PreparedDacl {
    /// Apply the preconditions and normalise. Spec: module documentation.
    pub(crate) fn prepare(sd: &SecurityDescriptor) -> Result<PreparedDacl, DaclRefusal> {
        // Rule 5a — DELIBERATE DEVIATION from [MS-DTYP] 2.5.3.2 / [MS-ADTS]
        // 5.1.3.3.1 (NULL DACL grants all): absent DACL ⇒ deny.
        // Spec: docs/11 §5 (D37); [MS-ADTS] 6.1.3 item 7.
        let dacl = match &sd.dacl {
            Some(dacl) => dacl,
            None => return Err(DaclRefusal::AbsentDacl),
        };
        // Rule 5b — DELIBERATE DEVIATION from [MS-DTYP] 2.5.3.2 (which
        // evaluates callback ACEs and has no case for the other types): any
        // other ACE type in the DACL ⇒ deny. Spec: docs/11 §5 (D37).
        let mut entries = Vec::with_capacity(dacl.aces.len());
        for ace in &dacl.aces {
            let entry = match ace {
                Ace::AccessAllowed(a) => entry(AceKind::Grant, a.ace_flags, a.mask.0, None, a.sid),
                Ace::AccessDenied(a) => entry(AceKind::Deny, a.ace_flags, a.mask.0, None, a.sid),
                Ace::AccessAllowedObject(o) => {
                    entry(AceKind::Grant, o.ace_flags, o.mask.0, o.object_type, o.sid)
                }
                Ace::AccessDeniedObject(o) => {
                    entry(AceKind::Deny, o.ace_flags, o.mask.0, o.object_type, o.sid)
                }
                Ace::SystemAudit(_) | Ace::SystemAuditObject { .. } | Ace::Unsupported(_) => {
                    return Err(DaclRefusal::UnsupportedAce)
                }
            };
            entries.push(entry);
        }
        // Structural validity: [MS-DTYP] 2.4.6 / 2.4.5 / 2.4.3 via dtyp, and
        // the AclRevision-versus-AceType table of [MS-DTYP] 2.4.5. Fail closed
        // (D40).
        if sd.validate().is_err() {
            return Err(DaclRefusal::InvalidDescriptor);
        }
        if !dacl
            .aces
            .iter()
            .all(|ace| acl_revision_permits(dacl.acl_revision, ace.ace_type()))
        {
            return Err(DaclRefusal::InvalidDescriptor);
        }
        Ok(PreparedDacl { entries })
    }

    /// The normalised entries, in DACL order.
    pub(crate) fn entries(&self) -> &[DaclEntry] {
        &self.entries
    }

    /// "the DACL does not have any ACE". Spec: [MS-ADTS] 5.1.3.3.2-5.1.3.3.4
    /// rule 2; [MS-DTYP] 2.5.3.2 ("an empty DACL").
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Does the DACL "contain ACEs from object owner"? Spec: [MS-DTYP]
    /// 2.5.3.2 (owner implicit rights condition). The phrase is not defined;
    /// per Q-050 (A-21) it is read in the way that suppresses the implicit
    /// grant most often (fail closed): any ACE, effective or inherit-only, whose
    /// trustee is the owner SID itself or OWNER_RIGHTS (S-1-3-4, which
    /// [MS-DTYP] 2.4.2.4 says makes "the system [ignore] the implicit
    /// READ_CONTROL and WRITE_DAC permissions for the object owner").
    pub(crate) fn contains_aces_from_owner(&self, owner: Option<&Sid>) -> bool {
        self.entries
            .iter()
            .any(|e| super::token::is_owner_rights(&e.sid) || owner.is_some_and(|o| e.sid == *o))
    }
}

/// Build one normalised entry. Spec: module documentation.
fn entry(kind: AceKind, flags: u8, mask: u32, object_type: Option<Guid>, sid: Sid) -> DaclEntry {
    DaclEntry {
        kind,
        inherit_only: flags & ace_flags::INHERIT_ONLY_ACE != 0,
        mask: effective_ace_rights(mask),
        object_type,
        sid,
    }
}
