//! ACL — header, ACE array, and consistency checks.
//!
//! Spec: [MS-DTYP] 2.4.5. Header: AclRevision (1), Sbz1 (1, MUST be zero),
//! AclSize (2), AceCount (2), Sbz2 (2, MUST be zero), followed by the ACEs.
//! "Access to each ACE MUST be computed by using the AclSize and AceCount
//! fields": the decoder walks exactly AceCount ACEs inside AclSize and requires
//! them to fill AclSize, which is "the size ... of the complete ACL, including
//! all ACEs".
//!
//! Also from 2.4.5: which ACE types each AclRevision permits, and which ACE
//! types are valid in a SACL versus a DACL. The DACL/SACL role is only known
//! inside a security descriptor; see [`Acl::check_sacl`] / [`Acl::check_dacl`].

use crate::access_mask::AccessMask;
use crate::ace::{ace_type, Ace, ACE_HEADER_LEN};
use crate::error::{Error, Result};
use crate::reader::Reader;

/// Size of the ACL header. Spec: [MS-DTYP] 2.4.5.
pub const ACL_HEADER_LEN: usize = 8;

/// ACL_REVISION. Spec: [MS-DTYP] 2.4.5.
pub const ACL_REVISION: u8 = 0x02;

/// ACL_REVISION_DS. Spec: [MS-DTYP] 2.4.5.
pub const ACL_REVISION_DS: u8 = 0x04;

/// Largest AclSize (unsigned 16-bit). Spec: [MS-DTYP] 2.4.5.
pub const MAX_ACL_SIZE: usize = 0xFFFF;

/// An access control list. Spec: [MS-DTYP] 2.4.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    /// AclRevision: [`ACL_REVISION`] or [`ACL_REVISION_DS`].
    /// Spec: [MS-DTYP] 2.4.5.
    pub acl_revision: u8,
    /// The ACEs, numbered 0 to n in order. Spec: [MS-DTYP] 2.4.5.
    pub aces: Vec<Ace>,
}

/// The ACE types ACL_REVISION permits. Spec: [MS-DTYP] 2.4.5 ("only AceTypes
/// 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present").
fn revision_2_permits(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ace_type::ACCESS_ALLOWED_ACE_TYPE
            | ace_type::ACCESS_DENIED_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_ACE_TYPE
            | ace_type::SYSTEM_ALARM_ACE_TYPE
            | ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | ace_type::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            | ace_type::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
    )
}

/// `true` if an ACL of `acl_revision` may contain an ACE of `ace_type`.
///
/// Spec: [MS-DTYP] 2.4.5, AclRevision table.
/// - ACL_REVISION (0x02): "only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12,
///   and 0x13 can be present" — exclusive.
/// - ACL_REVISION_DS (0x04): "AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are
///   allowed" — stated without "only", in contrast to revision 0x02, so it
///   adds the object ACE types to the revision-0x02 set: {0x00-0x03, 0x05-0x08,
///   0x11-0x13} (Q-022, resolved). That is also what lets directory DACLs mix
///   basic and object ACEs; types this crate does not decode still become
///   [`Ace::Unsupported`] and fail closed at access check.
///
/// Which of these may sit in a SACL versus a DACL (e.g. 0x11 is SACL-only) is
/// a separate rule: [`Acl::check_sacl`] / [`Acl::check_dacl`].
#[must_use]
pub fn acl_revision_permits(acl_revision: u8, ace_type: u8) -> bool {
    match acl_revision {
        ACL_REVISION => revision_2_permits(ace_type),
        ACL_REVISION_DS => {
            revision_2_permits(ace_type)
                || matches!(
                    ace_type,
                    ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        | ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE
                        | ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE
                        | ace_type::SYSTEM_ALARM_OBJECT_ACE_TYPE
                )
        }
        _ => false,
    }
}

/// `true` for the ACE types [MS-DTYP] 2.4.5 lists as the only valid ones in a
/// SACL: the auditing types, the label type, the resource attribute type and
/// the scoped policy type.
#[must_use]
pub fn is_valid_sacl_ace_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ace_type::SYSTEM_AUDIT_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | ace_type::SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | ace_type::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            | ace_type::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
    )
}

/// Reject an ACE type the ACL revision does not permit. Spec: [MS-DTYP] 2.4.5.
fn check_revision_permits(acl_revision: u8, ace_type: u8) -> Result<()> {
    if acl_revision_permits(acl_revision, ace_type) {
        Ok(())
    } else {
        Err(Error::AceTypeNotPermittedByAclRevision)
    }
}

/// AclRevision MUST be ACL_REVISION or ACL_REVISION_DS. Spec: [MS-DTYP] 2.4.5.
fn check_revision(acl_revision: u8) -> Result<()> {
    if acl_revision == ACL_REVISION || acl_revision == ACL_REVISION_DS {
        Ok(())
    } else {
        Err(Error::AclRevision)
    }
}

impl Acl {
    /// Decode one ACL that must occupy all of `input`.
    ///
    /// Spec: [MS-DTYP] 2.4.5; strict framing ([`Error::TrailingData`]).
    pub fn decode(input: &[u8]) -> Result<Acl> {
        let (acl, used) = Acl::decode_prefix(input)?;
        if used != input.len() {
            return Err(Error::TrailingData);
        }
        Ok(acl)
    }

    /// Decode one ACL at the start of `input`; return it and its AclSize.
    ///
    /// Spec: [MS-DTYP] 2.4.5.
    pub(crate) fn decode_prefix(input: &[u8]) -> Result<(Acl, usize)> {
        let mut r = Reader::new(input);
        let acl_revision = r.u8(Error::AclTruncated)?;
        let sbz1 = r.u8(Error::AclTruncated)?;
        let acl_size = usize::from(r.u16_le(Error::AclTruncated)?);
        let ace_count = usize::from(r.u16_le(Error::AclTruncated)?);
        let sbz2 = r.u16_le(Error::AclTruncated)?;

        check_revision(acl_revision)?;
        // Sbz1 / Sbz2 are reserved and MUST be zero. Spec: [MS-DTYP] 2.4.5.
        if sbz1 != 0 {
            return Err(Error::AclSbz1NonZero);
        }
        if sbz2 != 0 {
            return Err(Error::AclSbz2NonZero);
        }
        // AclSize includes the header. Spec: [MS-DTYP] 2.4.5.
        if acl_size < ACL_HEADER_LEN {
            return Err(Error::AclSizeTooSmall);
        }
        // Bound AclSize by the input before slicing (AGENTS.md §6).
        if acl_size > input.len() {
            return Err(Error::AclTruncated);
        }
        let region = &input[ACL_HEADER_LEN..acl_size];
        // Every ACE is at least its 4-byte header (2.4.4.1), so AceCount is
        // bounded by the region before any allocation from it (AGENTS.md §6).
        if ace_count > region.len() / ACE_HEADER_LEN {
            return Err(Error::AceCountExceedsAclSize);
        }
        let mut aces = Vec::with_capacity(ace_count);
        let mut pos = 0usize;
        for _ in 0..ace_count {
            // An ACE cut off by AclSize breaks the AclSize / AceCount rule.
            let (ace, used) = Ace::decode_prefix(&region[pos..]).map_err(|e| match e {
                Error::AceTruncated => Error::AceCountExceedsAclSize,
                other => other,
            })?;
            check_revision_permits(acl_revision, ace.ace_type())?;
            pos += used;
            aces.push(ace);
        }
        // The ACEs make up the complete ACL. Spec: [MS-DTYP] 2.4.5.
        if pos != region.len() {
            return Err(Error::AclSizeMismatch);
        }
        Ok((Acl { acl_revision, aces }, acl_size))
    }

    /// The canonical AclSize: the header plus the canonical size of each ACE.
    ///
    /// Spec: [MS-DTYP] 2.4.5.
    pub fn encoded_len(&self) -> Result<usize> {
        check_revision(self.acl_revision)?;
        let mut size = ACL_HEADER_LEN;
        for ace in &self.aces {
            check_revision_permits(self.acl_revision, ace.ace_type())?;
            size += ace.encoded_len()?;
            if size > MAX_ACL_SIZE {
                return Err(Error::AclTooLarge);
            }
        }
        Ok(size)
    }

    /// Append the canonical encoding to `out`. On error nothing is appended.
    ///
    /// Spec: [MS-DTYP] 2.4.5.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let size = self.encoded_len()?;
        // `size` <= MAX_ACL_SIZE, and each ACE is at least 4 bytes, so both
        // AclSize and AceCount fit 16 bits.
        let count = u16::try_from(self.aces.len()).map_err(|_| Error::AclTooLarge)?;
        out.reserve(size);
        out.push(self.acl_revision);
        out.push(0); // Sbz1. Spec: [MS-DTYP] 2.4.5.
        out.extend_from_slice(&(size as u16).to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2. Spec: [MS-DTYP] 2.4.5.
        let start = out.len() - ACL_HEADER_LEN;
        for ace in &self.aces {
            // Already validated by `encoded_len`; truncate defensively anyway.
            if let Err(e) = ace.encode_into(out) {
                out.truncate(start);
                return Err(e);
            }
        }
        Ok(())
    }

    /// The canonical encoding. Spec: [MS-DTYP] 2.4.5.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Check the rules for an ACL used as a SACL: only the SACL ACE types.
    ///
    /// Spec: [MS-DTYP] 2.4.5 ("The only valid ACE types for a SACL are ...";
    /// "The SACL MUST NOT contain ACEs that belong in the DACL").
    pub fn check_sacl(&self) -> Result<()> {
        for ace in &self.aces {
            if !is_valid_sacl_ace_type(ace.ace_type()) {
                return Err(Error::AceTypeNotValidInSacl);
            }
        }
        Ok(())
    }

    /// Check the rules for an ACL used as a DACL: no ACE type that belongs in
    /// the SACL, and no ACCESS_SYSTEM_SECURITY in any decoded ACE mask.
    ///
    /// Spec: [MS-DTYP] 2.4.5 ("the DACL MUST NOT contain ACE types that belong
    /// in the SACL"); 2.4.3 (ACCESS_SYSTEM_SECURITY "MUST NOT be set in an ACE
    /// that is part of a DACL").
    pub fn check_dacl(&self) -> Result<()> {
        for ace in &self.aces {
            if is_valid_sacl_ace_type(ace.ace_type()) {
                return Err(Error::AceTypeNotValidInDacl);
            }
            if let Some(mask) = ace.mask() {
                if mask.contains(AccessMask::ACCESS_SYSTEM_SECURITY) {
                    return Err(Error::AccessSystemSecurityInDacl);
                }
            }
        }
        Ok(())
    }
}
