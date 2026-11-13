//! ACE_HEADER and access control entries.
//!
//! Spec: [MS-DTYP] 2.4.4.1 (ACE_HEADER: AceType, AceFlags, AceSize), 2.4.4.2
//! (ACCESS_ALLOWED_ACE), 2.4.4.3 (ACCESS_ALLOWED_OBJECT_ACE), 2.4.4.4
//! (ACCESS_DENIED_ACE), 2.4.4.5 (ACCESS_DENIED_OBJECT_ACE), 2.4.4.10
//! (SYSTEM_AUDIT_ACE), 2.4.4.11 (SYSTEM_AUDIT_OBJECT_ACE).
//!
//! Every other AceType defined by 2.4.4.1 (callback, conditional, mandatory
//! label, resource attribute, scoped policy, and the "reserved for future use"
//! values) is decoded into [`Ace::Unsupported`], which keeps its type, flags
//! and raw bytes. Nothing is dropped: the access-check layer can see such an
//! ACE and fail closed on it. An AceType outside the 2.4.4.1 table is rejected.
//!
//! Size rules (2.4.4.1): AceSize MUST be a multiple of 4 and "can be greater
//! than the sum of the individual fields"; for the non-callback types such
//! additional data "is not interpreted and MUST be ignored". The decoder
//! therefore ignores it for the five typed variants without an
//! ApplicationData field; the encoder always emits the minimal AceSize, so
//! decode→encode is exact for minimal input and canonicalises padded input.
//! SYSTEM_AUDIT_OBJECT_ACE has its own ApplicationData field (2.4.4.11),
//! which is kept.
//!
//! Multi-byte fields are little-endian, as inside a self-relative security
//! descriptor (Spec: [MS-DTYP] 2.4.6; example in 2.5.1.4).

use crate::access_mask::AccessMask;
use crate::error::{Error, Result};
use crate::guid::{Guid, GUID_PACKET_LEN};
use crate::reader::Reader;
use crate::sid::Sid;

/// Size of ACE_HEADER: AceType (1), AceFlags (1), AceSize (2).
/// Spec: [MS-DTYP] 2.4.4.1.
pub const ACE_HEADER_LEN: usize = 4;

/// Largest AceSize that fits the 16-bit field and is a multiple of 4.
/// Spec: [MS-DTYP] 2.4.4.1 (AceSize is unsigned 16-bit, "MUST be a multiple
/// of 4").
pub const MAX_ACE_SIZE: usize = 0xFFFC;

/// AceType values. Spec: [MS-DTYP] 2.4.4.1, AceType table.
pub mod ace_type {
    /// ACCESS_ALLOWED_ACE_TYPE (2.4.4.2).
    pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    /// ACCESS_DENIED_ACE_TYPE (2.4.4.4).
    pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    /// SYSTEM_AUDIT_ACE_TYPE (2.4.4.10).
    pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
    /// SYSTEM_ALARM_ACE_TYPE — reserved for future use.
    pub const SYSTEM_ALARM_ACE_TYPE: u8 = 0x03;
    /// ACCESS_ALLOWED_COMPOUND_ACE_TYPE — reserved for future use.
    pub const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;
    /// ACCESS_ALLOWED_OBJECT_ACE_TYPE (2.4.4.3).
    pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
    /// ACCESS_DENIED_OBJECT_ACE_TYPE (2.4.4.5).
    pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
    /// SYSTEM_AUDIT_OBJECT_ACE_TYPE (2.4.4.11).
    pub const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
    /// SYSTEM_ALARM_OBJECT_ACE_TYPE — reserved for future use.
    pub const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8 = 0x08;
    /// ACCESS_ALLOWED_CALLBACK_ACE_TYPE (2.4.4.6).
    pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
    /// ACCESS_DENIED_CALLBACK_ACE_TYPE (2.4.4.7).
    pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x0A;
    /// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (2.4.4.8).
    pub const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;
    /// ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE (2.4.4.9).
    pub const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0C;
    /// SYSTEM_AUDIT_CALLBACK_ACE_TYPE (2.4.4.12).
    pub const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8 = 0x0D;
    /// SYSTEM_ALARM_CALLBACK_ACE_TYPE — reserved for future use.
    pub const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8 = 0x0E;
    /// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE (2.4.4.14).
    pub const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0F;
    /// SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE — reserved for future use.
    pub const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x10;
    /// SYSTEM_MANDATORY_LABEL_ACE_TYPE (2.4.4.13).
    pub const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
    /// SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE (2.4.4.15).
    pub const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
    /// SYSTEM_SCOPED_POLICY_ID_ACE_TYPE (2.4.4.16).
    pub const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;

    /// Highest AceType the 2.4.4.1 table defines; the table is contiguous
    /// from 0x00. Spec: [MS-DTYP] 2.4.4.1 ("MUST be one of the following").
    pub(crate) const HIGHEST_DEFINED: u8 = SYSTEM_SCOPED_POLICY_ID_ACE_TYPE;
}

/// AceFlags bits. Spec: [MS-DTYP] 2.4.4.1, AceFlags table.
pub mod ace_flags {
    /// OBJECT_INHERIT_ACE.
    pub const OBJECT_INHERIT_ACE: u8 = 0x01;
    /// CONTAINER_INHERIT_ACE.
    pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
    /// NO_PROPAGATE_INHERIT_ACE.
    pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
    /// INHERIT_ONLY_ACE.
    pub const INHERIT_ONLY_ACE: u8 = 0x08;
    /// INHERITED_ACE.
    pub const INHERITED_ACE: u8 = 0x10;
    /// SUCCESSFUL_ACCESS_ACE_FLAG.
    pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
    /// FAILED_ACCESS_ACE_FLAG.
    pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

    /// Union of every flag the table defines (0x20 is not defined).
    pub(crate) const DEFINED: u8 = OBJECT_INHERIT_ACE
        | CONTAINER_INHERIT_ACE
        | NO_PROPAGATE_INHERIT_ACE
        | INHERIT_ONLY_ACE
        | INHERITED_ACE
        | SUCCESSFUL_ACCESS_ACE_FLAG
        | FAILED_ACCESS_ACE_FLAG;
}

/// Object ACE `Flags`: ObjectType is present.
/// Spec: [MS-DTYP] 2.4.4.3, 2.4.4.5, 2.4.4.11.
pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0000_0001;
/// Object ACE `Flags`: InheritedObjectType is present.
/// Spec: [MS-DTYP] 2.4.4.3, 2.4.4.5, 2.4.4.11.
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0000_0002;

/// The ACE_HEADER fields. Spec: [MS-DTYP] 2.4.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AceHeader {
    /// AceType. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_type: u8,
    /// AceFlags. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_flags: u8,
    /// AceSize, in bytes, of the whole ACE. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_size: u16,
}

/// The body shared by ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE and
/// SYSTEM_AUDIT_ACE: Header, Mask, Sid.
///
/// Spec: [MS-DTYP] 2.4.4.2, 2.4.4.4, 2.4.4.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskSidAce {
    /// AceFlags from the ACE_HEADER. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_flags: u8,
    /// Mask. Spec: [MS-DTYP] 2.4.4.2 / 2.4.4.4 / 2.4.4.10.
    pub mask: AccessMask,
    /// Sid of the trustee. Spec: [MS-DTYP] 2.4.4.2 / 2.4.4.4 / 2.4.4.10.
    pub sid: Sid,
}

/// The body shared by the object ACEs: Header, Mask, Flags, ObjectType,
/// InheritedObjectType, Sid.
///
/// `Flags` is not stored: it is exactly which of `object_type` /
/// `inherited_object_type` are present, so a value cannot be inconsistent.
///
/// Spec: [MS-DTYP] 2.4.4.3, 2.4.4.5, 2.4.4.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectAce {
    /// AceFlags from the ACE_HEADER. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_flags: u8,
    /// Mask. Spec: [MS-DTYP] 2.4.4.3 / 2.4.4.5 / 2.4.4.11.
    pub mask: AccessMask,
    /// ObjectType, present iff ACE_OBJECT_TYPE_PRESENT. Spec: [MS-DTYP] 2.4.4.3.
    pub object_type: Option<Guid>,
    /// InheritedObjectType, present iff ACE_INHERITED_OBJECT_TYPE_PRESENT.
    /// Spec: [MS-DTYP] 2.4.4.3.
    pub inherited_object_type: Option<Guid>,
    /// Sid of the trustee. Spec: [MS-DTYP] 2.4.4.3.
    pub sid: Sid,
}

/// An ACE whose AceType is defined by [MS-DTYP] 2.4.4.1 but is not decoded by
/// this crate. Kept whole so that it is never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedAce {
    /// AceType. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_type: u8,
    /// AceFlags. Spec: [MS-DTYP] 2.4.4.1.
    pub ace_flags: u8,
    /// The `AceSize - 4` bytes that follow the ACE_HEADER, uninterpreted.
    pub body: Vec<u8>,
}

/// An access control entry. Spec: [MS-DTYP] 2.4.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ace {
    /// ACCESS_ALLOWED_ACE (type 0x00). Spec: [MS-DTYP] 2.4.4.2.
    AccessAllowed(MaskSidAce),
    /// ACCESS_DENIED_ACE (type 0x01). Spec: [MS-DTYP] 2.4.4.4.
    AccessDenied(MaskSidAce),
    /// SYSTEM_AUDIT_ACE (type 0x02). Spec: [MS-DTYP] 2.4.4.10.
    SystemAudit(MaskSidAce),
    /// ACCESS_ALLOWED_OBJECT_ACE (type 0x05). Spec: [MS-DTYP] 2.4.4.3.
    AccessAllowedObject(ObjectAce),
    /// ACCESS_DENIED_OBJECT_ACE (type 0x06). Spec: [MS-DTYP] 2.4.4.5.
    AccessDeniedObject(ObjectAce),
    /// SYSTEM_AUDIT_OBJECT_ACE (type 0x07), including its optional
    /// ApplicationData. Spec: [MS-DTYP] 2.4.4.11.
    SystemAuditObject {
        /// Header, Mask, Flags, ObjectType, InheritedObjectType, Sid.
        ace: ObjectAce,
        /// ApplicationData: the bytes after the Sid, up to AceSize.
        /// Spec: [MS-DTYP] 2.4.4.11.
        application_data: Vec<u8>,
    },
    /// Any other AceType defined by 2.4.4.1, kept whole (fail closed upstream).
    Unsupported(UnsupportedAce),
}

/// `true` for the AceTypes this crate decodes into typed variants.
#[must_use]
pub fn is_supported_ace_type(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ace_type::ACCESS_ALLOWED_ACE_TYPE
            | ace_type::ACCESS_DENIED_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_ACE_TYPE
            | ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE
            | ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE
    )
}

impl Ace {
    /// The AceType this value encodes as. Spec: [MS-DTYP] 2.4.4.1.
    #[must_use]
    pub fn ace_type(&self) -> u8 {
        match self {
            Ace::AccessAllowed(_) => ace_type::ACCESS_ALLOWED_ACE_TYPE,
            Ace::AccessDenied(_) => ace_type::ACCESS_DENIED_ACE_TYPE,
            Ace::SystemAudit(_) => ace_type::SYSTEM_AUDIT_ACE_TYPE,
            Ace::AccessAllowedObject(_) => ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            Ace::AccessDeniedObject(_) => ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE,
            Ace::SystemAuditObject { .. } => ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE,
            Ace::Unsupported(u) => u.ace_type,
        }
    }

    /// The AceFlags. Spec: [MS-DTYP] 2.4.4.1.
    #[must_use]
    pub fn ace_flags(&self) -> u8 {
        match self {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => a.ace_flags,
            Ace::AccessAllowedObject(a)
            | Ace::AccessDeniedObject(a)
            | Ace::SystemAuditObject { ace: a, .. } => a.ace_flags,
            Ace::Unsupported(u) => u.ace_flags,
        }
    }

    /// The Mask of a typed ACE; `None` for [`Ace::Unsupported`], whose bytes
    /// are not interpreted. Spec: [MS-DTYP] 2.4.4.2-2.4.4.11.
    #[must_use]
    pub fn mask(&self) -> Option<AccessMask> {
        match self {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => Some(a.mask),
            Ace::AccessAllowedObject(a)
            | Ace::AccessDeniedObject(a)
            | Ace::SystemAuditObject { ace: a, .. } => Some(a.mask),
            Ace::Unsupported(_) => None,
        }
    }

    /// Decode one ACE that must occupy all of `input`.
    ///
    /// Spec: [MS-DTYP] 2.4.4.1; strict framing ([`Error::TrailingData`]).
    pub fn decode(input: &[u8]) -> Result<Ace> {
        let (ace, used) = Ace::decode_prefix(input)?;
        if used != input.len() {
            return Err(Error::TrailingData);
        }
        Ok(ace)
    }

    /// Decode one ACE at the start of `input`; return it and its AceSize.
    ///
    /// Spec: [MS-DTYP] 2.4.4.1 and the per-type sections.
    pub(crate) fn decode_prefix(input: &[u8]) -> Result<(Ace, usize)> {
        let mut r = Reader::new(input);
        let header = AceHeader {
            ace_type: r.u8(Error::AceTruncated)?,
            ace_flags: r.u8(Error::AceTruncated)?,
            ace_size: r.u16_le(Error::AceTruncated)?,
        };
        // AceType MUST be one of the table values. Spec: [MS-DTYP] 2.4.4.1.
        if header.ace_type > ace_type::HIGHEST_DEFINED {
            return Err(Error::AceTypeUndefined);
        }
        // AceFlags is a combination of the table values. Spec: 2.4.4.1.
        if header.ace_flags & !ace_flags::DEFINED != 0 {
            return Err(Error::AceFlagsUndefined);
        }
        let size = usize::from(header.ace_size);
        // AceSize covers at least its own header. Spec: [MS-DTYP] 2.4.4.1.
        if size < ACE_HEADER_LEN {
            return Err(Error::AceSizeTooSmall);
        }
        // AceSize MUST be a multiple of 4. Spec: [MS-DTYP] 2.4.4.1.
        if size % 4 != 0 {
            return Err(Error::AceSizeNotMultipleOf4);
        }
        // Bound AceSize by the input before slicing (AGENTS.md §6).
        if size > input.len() {
            return Err(Error::AceTruncated);
        }
        let body = &input[ACE_HEADER_LEN..size];
        let flags = header.ace_flags;
        let ace = match header.ace_type {
            ace_type::ACCESS_ALLOWED_ACE_TYPE => Ace::AccessAllowed(decode_mask_sid(flags, body)?),
            ace_type::ACCESS_DENIED_ACE_TYPE => Ace::AccessDenied(decode_mask_sid(flags, body)?),
            ace_type::SYSTEM_AUDIT_ACE_TYPE => Ace::SystemAudit(decode_mask_sid(flags, body)?),
            ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                Ace::AccessAllowedObject(decode_object(flags, body)?.0)
            }
            ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE => {
                Ace::AccessDeniedObject(decode_object(flags, body)?.0)
            }
            ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
                let (ace, used) = decode_object(flags, body)?;
                // ApplicationData: the rest of AceSize. Spec: 2.4.4.11.
                Ace::SystemAuditObject {
                    ace,
                    application_data: body[used..].to_vec(),
                }
            }
            other => Ace::Unsupported(UnsupportedAce {
                ace_type: other,
                ace_flags: flags,
                // Bounded: `body` is within the input (checked above).
                body: body.to_vec(),
            }),
        };
        Ok((ace, size))
    }

    /// The canonical AceSize of this value: the header plus exactly its fields.
    ///
    /// Returns an error if the value cannot be encoded (see [`Ace::encode`]).
    /// Spec: [MS-DTYP] 2.4.4.1.
    pub fn encoded_len(&self) -> Result<usize> {
        if self.ace_flags() & !ace_flags::DEFINED != 0 {
            return Err(Error::AceFlagsUndefined);
        }
        let size = match self {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => {
                // Header + Mask + Sid. Spec: [MS-DTYP] 2.4.4.2.
                ACE_HEADER_LEN + 4 + a.sid.encoded_len()
            }
            Ace::AccessAllowedObject(a) | Ace::AccessDeniedObject(a) => object_len(a),
            Ace::SystemAuditObject {
                ace,
                application_data,
            } => object_len(ace) + application_data.len(),
            Ace::Unsupported(u) => {
                if u.ace_type > ace_type::HIGHEST_DEFINED {
                    return Err(Error::AceTypeUndefined);
                }
                if is_supported_ace_type(u.ace_type) {
                    return Err(Error::UnsupportedAceHasSupportedType);
                }
                ACE_HEADER_LEN + u.body.len()
            }
        };
        if size % 4 != 0 {
            return Err(Error::AceSizeNotMultipleOf4);
        }
        if size > MAX_ACE_SIZE {
            return Err(Error::AceTooLarge);
        }
        Ok(size)
    }

    /// Append the canonical encoding (minimal AceSize) to `out`.
    ///
    /// On error nothing is appended. Spec: [MS-DTYP] 2.4.4.1-2.4.4.11.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let size = self.encoded_len()?;
        out.reserve(size);
        out.push(self.ace_type());
        out.push(self.ace_flags());
        // `size` <= MAX_ACE_SIZE, so it fits AceSize (16-bit).
        out.extend_from_slice(&(size as u16).to_le_bytes());
        match self {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) | Ace::SystemAudit(a) => {
                out.extend_from_slice(&a.mask.0.to_le_bytes());
                a.sid.encode_into(out);
            }
            Ace::AccessAllowedObject(a) | Ace::AccessDeniedObject(a) => encode_object(a, out),
            Ace::SystemAuditObject {
                ace,
                application_data,
            } => {
                encode_object(ace, out);
                out.extend_from_slice(application_data);
            }
            Ace::Unsupported(u) => out.extend_from_slice(&u.body),
        }
        Ok(())
    }

    /// The canonical encoding (minimal AceSize).
    ///
    /// Fails if AceFlags has an undefined bit, an [`Ace::Unsupported`] value
    /// carries a supported or undefined AceType, or the size is not a multiple
    /// of 4 or exceeds [`MAX_ACE_SIZE`]. Spec: [MS-DTYP] 2.4.4.1.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

/// Decode Mask then Sid from an ACE body; any further bytes up to AceSize are
/// ignored. Spec: [MS-DTYP] 2.4.4.2 / 2.4.4.4 / 2.4.4.10; 2.4.4.1 (additional
/// data "is not interpreted and MUST be ignored").
///
/// The Sid is always required. 2.4.4.10 mentions a SYSTEM_AUDIT_ACE whose
/// application "does not specify a SID", but defines no encoding for that, so
/// it is rejected (fail closed) — Q-025.
fn decode_mask_sid(ace_flags: u8, body: &[u8]) -> Result<MaskSidAce> {
    let mut r = Reader::new(body);
    let mask = AccessMask(r.u32_le(Error::AceSizeTooSmall)?);
    let (sid, _used) = decode_sid_in_ace(&body[r.position()..])?;
    Ok(MaskSidAce {
        ace_flags,
        mask,
        sid,
    })
}

/// Decode an object ACE body; return it and the bytes used (so that
/// SYSTEM_AUDIT_OBJECT_ACE can keep its ApplicationData).
///
/// Spec: [MS-DTYP] 2.4.4.3 / 2.4.4.5 / 2.4.4.11. ObjectType "is present only
/// if" ACE_OBJECT_TYPE_PRESENT is set, and InheritedObjectType likewise for
/// ACE_INHERITED_OBJECT_TYPE_PRESENT; a field that is not present takes no
/// bytes, so the Sid follows whatever is present. (Reading the 16-byte fields
/// as always occupying space would contradict "present only if".)
fn decode_object(ace_flags: u8, body: &[u8]) -> Result<(ObjectAce, usize)> {
    let mut r = Reader::new(body);
    let mask = AccessMask(r.u32_le(Error::AceSizeTooSmall)?);
    let flags = r.u32_le(Error::AceSizeTooSmall)?;
    // Flags is one or more of the defined values. Spec: [MS-DTYP] 2.4.4.3.
    if flags & !(ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 {
        return Err(Error::ObjectAceFlagsUndefined);
    }
    let object_type = if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        Some(Guid::from_packet(
            &r.array::<GUID_PACKET_LEN>(Error::AceSizeTooSmall)?,
        ))
    } else {
        None
    };
    let inherited_object_type = if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        Some(Guid::from_packet(
            &r.array::<GUID_PACKET_LEN>(Error::AceSizeTooSmall)?,
        ))
    } else {
        None
    };
    let start = r.position();
    let (sid, sid_len) = decode_sid_in_ace(&body[start..])?;
    let ace = ObjectAce {
        ace_flags,
        mask,
        object_type,
        inherited_object_type,
        sid,
    };
    Ok((ace, start + sid_len))
}

/// Decode the trailing Sid of an ACE. A SID cut short by AceSize is reported
/// as [`Error::AceSizeTooSmall`] (the AceSize rule is the one broken).
/// Spec: [MS-DTYP] 2.4.4.1, 2.4.2.2.
fn decode_sid_in_ace(rest: &[u8]) -> Result<(Sid, usize)> {
    Sid::decode_prefix(rest).map_err(|e| match e {
        Error::SidTruncated => Error::AceSizeTooSmall,
        other => other,
    })
}

/// Header + Mask + Flags + present GUIDs + Sid. Spec: [MS-DTYP] 2.4.4.3.
fn object_len(a: &ObjectAce) -> usize {
    let guids =
        usize::from(a.object_type.is_some()) + usize::from(a.inherited_object_type.is_some());
    ACE_HEADER_LEN + 4 + 4 + GUID_PACKET_LEN * guids + a.sid.encoded_len()
}

/// Write Mask, Flags (derived from which GUIDs are present), the present
/// GUIDs, then Sid. Spec: [MS-DTYP] 2.4.4.3 / 2.4.4.5 / 2.4.4.11.
fn encode_object(a: &ObjectAce, out: &mut Vec<u8>) {
    out.extend_from_slice(&a.mask.0.to_le_bytes());
    let mut flags = 0u32;
    if a.object_type.is_some() {
        flags |= ACE_OBJECT_TYPE_PRESENT;
    }
    if a.inherited_object_type.is_some() {
        flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
    }
    out.extend_from_slice(&flags.to_le_bytes());
    if let Some(guid) = &a.object_type {
        out.extend_from_slice(&guid.to_packet());
    }
    if let Some(guid) = &a.inherited_object_type {
        out.extend_from_slice(&guid.to_packet());
    }
    a.sid.encode_into(out);
}
