//! Error type for the security data-type codec.
//!
//! Hand-rolled, zero-dependency (docs/CLEAN-ROOM.md). Every variant corresponds to one
//! structural rule that the decoder enforces (or that the canonical encoder
//! refuses to break). Fail closed: any malformed or inconsistent
//! input is a distinct `Err`, never a panic and never a silent repair
//! (docs/CLEAN-ROOM.md; docs/32 §8).
//!
//! Security: no variant carries attacker-supplied contents — only the fact of
//! which rule failed.
//!
//! Spec references cite [MS-DTYP] v20241119 (protocol revision 42.0). Variants
//! marked "Q-0xx" enforce a reading recorded (and resolved) in the question
//! file of that number under `docs/questions/`.

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A decode or encode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- GUID ([MS-DTYP] 2.3.4.2) ----
    /// A GUID packet was not exactly 16 bytes. Spec: [MS-DTYP] 2.3.4.2.
    GuidLength,
    /// A GUID text was not exactly the lower-case `8-4-4-4-12` form (36
    /// octets, "-" at offsets 8, 13, 18 and 23, lower-case hexadecimal
    /// digits elsewhere). Spec: [MS-DTYP] 2.5.1.1 (the SDDL `guid`
    /// production); [MS-DRSR] 5.16.3.16; PENDING-OWNER A-31.
    GuidTextSyntax,

    // ---- SID packet ([MS-DTYP] 2.4.2.2) ----
    /// Input ended before the 8 fixed bytes and the `SubAuthorityCount`
    /// 32-bit SubAuthority values. Spec: [MS-DTYP] 2.4.2.2.
    SidTruncated,
    /// `Revision` was not 0x01. Spec: [MS-DTYP] 2.4.2.2 ("MUST be set to 0x01").
    SidRevision,
    /// `SubAuthorityCount` exceeded 15 (packet or constructor). Spec:
    /// [MS-DTYP] 2.4.2.2 ("The maximum number of elements allowed is 15").
    SidTooManySubAuthorities,

    // ---- SID string ([MS-DTYP] 2.4.2.1) ----
    /// The string does not match the SID ABNF: prefix "S-1-" (any letter
    /// case), "-" separators, 1 to 10 decimal digits per decimal number, or
    /// "0x" followed by exactly 12 HEXDIG. Spec: [MS-DTYP] 2.4.2.1; RFC 5234
    /// §2.3, Appendix B.1.
    SidStringSyntax,
    /// A decimal IdentifierAuthority or SubAuthority had a leading "0".
    /// Spec: [MS-DTYP] 2.4.2.1 ("No leading "0" characters are allowed").
    SidStringLeadingZero,
    /// A SubAuthority exceeded the unsigned 32-bit range.
    /// Spec: [MS-DTYP] 2.4.2.1, 2.4.2.2.
    SidStringValueOutOfRange,
    /// The IdentifierAuthority used the form the 2.4.2.1 comments do not
    /// assign to its value: decimal for a value >= 2^32, or hexadecimal for a
    /// value < 2^32. Only the canonical form is accepted.
    /// Spec: [MS-DTYP] 2.4.2.1.
    SidStringNonCanonicalAuthority,

    // ---- ACE ([MS-DTYP] 2.4.4.x) ----
    /// Input ended before the 4-byte ACE_HEADER, or `AceSize` ran past the
    /// available input. Spec: [MS-DTYP] 2.4.4.1.
    AceTruncated,
    /// `AceSize` was smaller than the header plus the fixed fields and SID the
    /// ACE type requires. Spec: [MS-DTYP] 2.4.4.1-2.4.4.11.
    AceSizeTooSmall,
    /// `AceSize` was not a multiple of 4. Spec: [MS-DTYP] 2.4.4.1 ("MUST be a
    /// multiple of 4").
    AceSizeNotMultipleOf4,
    /// `AceType` was not one of the values the ACE_HEADER table defines
    /// (0x00-0x13). Spec: [MS-DTYP] 2.4.4.1 ("MUST be one of the following").
    AceTypeUndefined,
    /// `AceFlags` had a bit set that the ACE_HEADER flag table does not
    /// define. Spec: [MS-DTYP] 2.4.4.1 ("a combination of the following").
    AceFlagsUndefined,
    /// An object ACE `Flags` field had a bit other than
    /// ACE_OBJECT_TYPE_PRESENT / ACE_INHERITED_OBJECT_TYPE_PRESENT.
    /// Spec: [MS-DTYP] 2.4.4.3, 2.4.4.5, 2.4.4.11.
    ObjectAceFlagsUndefined,
    /// Encoder: an "unsupported" ACE carried an `AceType` this crate decodes
    /// into a typed variant, so the value has no single canonical form.
    UnsupportedAceHasSupportedType,
    /// Encoder: the ACE would exceed the largest `AceSize` a 16-bit field can
    /// hold while remaining a multiple of 4. Spec: [MS-DTYP] 2.4.4.1.
    AceTooLarge,

    // ---- ACL ([MS-DTYP] 2.4.5) ----
    /// Input ended before the 8-byte ACL header, or before `AclSize` bytes.
    /// Spec: [MS-DTYP] 2.4.5.
    AclTruncated,
    /// `AclRevision` was neither ACL_REVISION (0x02) nor ACL_REVISION_DS
    /// (0x04). Spec: [MS-DTYP] 2.4.5 ("MUST be set to one of the following").
    AclRevision,
    /// `Sbz1` was not zero. Spec: [MS-DTYP] 2.4.5 ("MUST be set to zero").
    AclSbz1NonZero,
    /// `Sbz2` was not zero. Spec: [MS-DTYP] 2.4.5 ("MUST be set to zero").
    AclSbz2NonZero,
    /// `AclSize` was smaller than the 8-byte ACL header. Spec: [MS-DTYP] 2.4.5.
    AclSizeTooSmall,
    /// `AceCount` ACEs cannot fit, or an ACE ran past `AclSize`.
    /// Spec: [MS-DTYP] 2.4.5 (ACEs are located using AclSize and AceCount).
    AceCountExceedsAclSize,
    /// The `AceCount` ACEs ended before `AclSize` bytes (unaccounted bytes
    /// inside the ACL). Spec: [MS-DTYP] 2.4.5 (AclSize is "the size ... of the
    /// complete ACL, including all ACEs").
    AclSizeMismatch,
    /// An ACE type the ACL revision does not permit: ACL_REVISION allows
    /// "only" 0x00-0x03 and 0x11-0x13; ACL_REVISION_DS adds 0x05-0x08 to that
    /// set (Q-022). Spec: [MS-DTYP] 2.4.5.
    AceTypeNotPermittedByAclRevision,
    /// Encoder: the ACL would exceed the 16-bit `AclSize`. Spec: [MS-DTYP] 2.4.5.
    AclTooLarge,

    // ---- SECURITY_DESCRIPTOR, self-relative ([MS-DTYP] 2.4.6) ----
    /// Input was shorter than the 20-byte fixed portion. Spec: [MS-DTYP] 2.4.6.
    SdTruncated,
    /// `Revision` was not 1. Spec: [MS-DTYP] 2.4.6 ("MUST be set to one").
    SdRevision,
    /// The Self-Relative (SR) control bit was clear. Spec: [MS-DTYP] 2.4.6
    /// ("The Self Relative (SR) bit MUST be set").
    SdNotSelfRelative,
    /// SP clear but `OffsetSacl` non-zero (decoder), or a SACL supplied while
    /// SP is clear (encoder). Spec: [MS-DTYP] 2.4.6 ("if the SP flag is not
    /// set, this field MUST be set to zero").
    SaclOffsetWithoutPresentFlag,
    /// SP set but `OffsetSacl` zero / no SACL. Spec: [MS-DTYP] 2.4.6 (Sacl
    /// "MUST be present if the SP flag is set").
    SaclPresentWithoutOffset,
    /// DP clear but `OffsetDacl` non-zero (decoder), or a DACL supplied while
    /// DP is clear (encoder). Spec: [MS-DTYP] 2.4.6.
    DaclOffsetWithoutPresentFlag,
    /// DP set but `OffsetDacl` zero / no DACL. Spec: [MS-DTYP] 2.4.6 (Dacl
    /// "MUST be present if the DP flag is set").
    DaclPresentWithoutOffset,
    /// `OffsetOwner` zero while OD is clear: the offset "must be a valid
    /// offset if the OD flag is not set" (Q-023). Spec: [MS-DTYP] 2.4.6.
    OwnerAbsentNotDefaulted,
    /// `OffsetGroup` zero while GD is clear: the offset "must be a valid
    /// offset if the GD flag is not set" (Q-023). Spec: [MS-DTYP] 2.4.6.
    GroupAbsentNotDefaulted,
    /// A non-zero offset pointed into the 20-byte fixed portion.
    /// Spec: [MS-DTYP] 2.4.6 (offsets locate the pointer target fields that
    /// follow the fixed portion).
    OffsetIntoHeader,
    /// A non-zero offset was at or beyond the end of the input.
    /// Spec: [MS-DTYP] 2.4.6 ("must be a valid offset").
    OffsetOutOfRange,
    /// Two of OwnerSid / GroupSid / Sacl / Dacl occupy overlapping bytes.
    /// Project strictness rule, see Q-024. Spec context: [MS-DTYP] 2.4.6.
    ComponentsOverlap,
    /// Bytes after the fixed portion are not covered by any component (a gap
    /// or trailing data). Project strictness rule, see Q-024.
    /// Spec context: [MS-DTYP] 2.4.6 ("requires no padding").
    UnreferencedBytes,
    /// A SACL contained an ACE type that is not valid in a SACL.
    /// Spec: [MS-DTYP] 2.4.5 ("The only valid ACE types for a SACL are ...").
    AceTypeNotValidInSacl,
    /// A DACL contained an ACE type that belongs in the SACL.
    /// Spec: [MS-DTYP] 2.4.5 ("the DACL MUST NOT contain ACE types that belong
    /// in the SACL").
    AceTypeNotValidInDacl,
    /// A DACL ACE had ACCESS_SYSTEM_SECURITY set in its mask.
    /// Spec: [MS-DTYP] 2.4.3 ("This bit MUST NOT be set in an ACE that is part
    /// of a DACL").
    AccessSystemSecurityInDacl,

    // ---- framing ----
    /// Bytes remained after a complete stand-alone SID, ACE or ACL.
    /// Strict framing (docs/CLEAN-ROOM.md).
    TrailingData,

    // ---- CreateSecurityDescriptor ([MS-DTYP] 2.5.3.4) ----
    /// A CreatorDescriptor was supplied. Only CreatorDescriptor = NULL is
    /// built (project decision A-76, Q-294; Q-336). Spec: [MS-DTYP] 2.5.3.4.1.
    CreatorDescriptorNotSupported,
    /// DEFAULT_OWNER_FROM_PARENT was set but there is no parent descriptor or
    /// it has no owner, so the new descriptor would have no owner (fail
    /// closed; [MS-ADTS] 6.1.3 item 1). Spec: [MS-DTYP] 2.5.3.4.1 Step 1.
    NewDescriptorOwnerAbsent,
    /// DEFAULT_GROUP_FROM_PARENT was set but there is no parent descriptor or
    /// it has no group (fail closed). Spec: [MS-DTYP] 2.5.3.4.1 Step 2.
    NewDescriptorGroupAbsent,
    /// The computed ACL would need an ACE this crate keeps as
    /// `Ace::Unsupported` (an inheritable one in the parent ACL, or one in the
    /// token's default DACL): PostProcessACL needs its Sid and Mask, which are
    /// not interpreted. Project fail-closed rule. Spec: [MS-DTYP] 2.5.3.4.4,
    /// 2.5.3.4.7.
    UnsupportedAceInComputedAcl,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::GuidLength => "GUID packet is not 16 bytes",
            Error::GuidTextSyntax => "GUID text is not the lower-case 8-4-4-4-12 form",
            Error::SidTruncated => "SID packet truncated",
            Error::SidRevision => "SID revision is not 1",
            Error::SidTooManySubAuthorities => "SID has more than 15 sub-authorities",
            Error::SidStringSyntax => "SID string does not match the SID syntax",
            Error::SidStringLeadingZero => "SID string number has a leading zero",
            Error::SidStringValueOutOfRange => "SID string number out of range",
            Error::SidStringNonCanonicalAuthority => {
                "SID string authority not in its canonical decimal/hex form"
            }
            Error::AceTruncated => "ACE truncated",
            Error::AceSizeTooSmall => "AceSize smaller than the ACE fields",
            Error::AceSizeNotMultipleOf4 => "AceSize is not a multiple of 4",
            Error::AceTypeUndefined => "AceType is not a defined value",
            Error::AceFlagsUndefined => "AceFlags has an undefined bit",
            Error::ObjectAceFlagsUndefined => "object ACE Flags has an undefined bit",
            Error::UnsupportedAceHasSupportedType => "unsupported ACE carries a supported type",
            Error::AceTooLarge => "ACE too large for AceSize",
            Error::AclTruncated => "ACL truncated",
            Error::AclRevision => "AclRevision is not 2 or 4",
            Error::AclSbz1NonZero => "ACL Sbz1 is not zero",
            Error::AclSbz2NonZero => "ACL Sbz2 is not zero",
            Error::AclSizeTooSmall => "AclSize smaller than the ACL header",
            Error::AceCountExceedsAclSize => "AceCount ACEs do not fit in AclSize",
            Error::AclSizeMismatch => "ACEs do not fill AclSize exactly",
            Error::AceTypeNotPermittedByAclRevision => "ACE type not permitted by AclRevision",
            Error::AclTooLarge => "ACL too large for AclSize",
            Error::SdTruncated => "security descriptor shorter than its fixed portion",
            Error::SdRevision => "security descriptor revision is not 1",
            Error::SdNotSelfRelative => "security descriptor SR bit is clear",
            Error::SaclOffsetWithoutPresentFlag => "SACL offset or SACL without SP",
            Error::SaclPresentWithoutOffset => "SP set without a SACL",
            Error::DaclOffsetWithoutPresentFlag => "DACL offset or DACL without DP",
            Error::DaclPresentWithoutOffset => "DP set without a DACL",
            Error::OwnerAbsentNotDefaulted => "owner absent while OD is clear",
            Error::GroupAbsentNotDefaulted => "group absent while GD is clear",
            Error::OffsetIntoHeader => "offset points into the fixed portion",
            Error::OffsetOutOfRange => "offset beyond the end of the input",
            Error::ComponentsOverlap => "security descriptor components overlap",
            Error::UnreferencedBytes => "security descriptor has unreferenced bytes",
            Error::AceTypeNotValidInSacl => "ACE type not valid in a SACL",
            Error::AceTypeNotValidInDacl => "ACE type not valid in a DACL",
            Error::AccessSystemSecurityInDacl => "ACCESS_SYSTEM_SECURITY set in a DACL ACE",
            Error::TrailingData => "unexpected trailing data",
            Error::CreatorDescriptorNotSupported => {
                "a creator security descriptor is not supported"
            }
            Error::NewDescriptorOwnerAbsent => "the new security descriptor would have no owner",
            Error::NewDescriptorGroupAbsent => "the new security descriptor would have no group",
            Error::UnsupportedAceInComputedAcl => {
                "an uninterpreted ACE type would have to be inherited"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
